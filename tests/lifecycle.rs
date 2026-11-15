//! Reload, certificate rotation and shutdown of the real binary under systemd's
//! `Type=notify-reload` protocol, observed through a fake `NOTIFY_SOCKET` and the bytes clients
//! get over HTTP/1.1, HTTP/2 and HTTP/3.

mod support;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde_json::{Value, json};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use support::clients::{self, H2, H3, Reply, reserve_udp, served_chain};
use support::{Client, Origin, PATIENCE, Proxy, Reserved, ok, sha256};

const HOST: &str = "kept.test";

fn plain_site(routes: Value) -> Value {
    json!({ "name": "plain", "hosts": ["*"], "routes": routes })
}

/// A TLS site for [`HOST`] on `addr` (TCP, and QUIC when `http3`).
fn tls_site(addr: SocketAddr, cert: &Path, key: &Path, http3: bool, routes: Value) -> Value {
    json!({
        "name": "tls",
        "hosts": [HOST],
        "listen": [addr],
        "tls": { "cert": cert, "key": key, "redirectHttp": false, "http3": http3 },
        "routes": routes,
    })
}

/// `CLOCK_MONOTONIC` in microseconds, the clock systemd reads `MONOTONIC_USEC` against.
fn monotonic_usec() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
}

fn fingerprints(chain: &[CertificateDer<'_>]) -> Vec<String> {
    chain.iter().map(|der| sha256(der)).collect()
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = support::base64(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

fn fixture(file: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(file),
    )
    .unwrap()
}

/// Whether nothing accepts on `addr`. Some kernels answer a SYN to a closed port only by
/// silence, so a connection attempt that is not answered at once counts too.
fn refused(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err()
}

fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);

impl Gate {
    fn open(&self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
    fn wait(&self, limit: Duration) -> bool {
        let (open, cv) = &*self.0;
        let guard = cv
            .wait_timeout_while(open.lock().unwrap(), limit, |open| !*open)
            .unwrap();
        *guard.0
    }
}

#[test]
fn reload_and_stop_follow_the_notify_reload_protocol() {
    let mut proxy = Proxy::start(json!([plain_site(
        json!([{ "respond": { "body": "one" } }])
    )]));
    assert_eq!(proxy.ready, "READY=1\nSTATUS=serving generation 1");
    let mut conn = proxy.client();
    assert_eq!(conn.get("/").text(), "one");

    proxy.rewrite(json!([plain_site(
        json!([{ "respond": { "body": "two" } }])
    )]));
    let before = monotonic_usec();
    proxy.signal(libc::SIGHUP);
    let reloading = proxy.notification();
    let usec: u64 = reloading
        .strip_prefix("RELOADING=1\nMONOTONIC_USEC=")
        .unwrap_or_else(|| panic!("RELOADING=1 with MONOTONIC_USEC first: {reloading:?}"))
        .parse()
        .unwrap();
    assert!(
        before <= usec && usec <= monotonic_usec(),
        "MONOTONIC_USEC is the time of the reload on CLOCK_MONOTONIC"
    );
    assert_eq!(proxy.notification(), "READY=1\nSTATUS=serving generation 2");
    assert_eq!(
        conn.get("/").text(),
        "two",
        "the next request on a kept connection runs the new generation"
    );

    proxy.rewrite_raw(b"{ \"version\": 1, \"sites\": [");
    let status = proxy.reload();
    assert!(
        status.starts_with("reload failed, still serving generation 2: "),
        "{status}"
    );
    assert_eq!(conn.get("/").text(), "two", "the old generation answers");

    proxy.rewrite(json!([plain_site(
        json!([{ "respond": { "body": "{lang}" } }])
    )]));
    let status = proxy.reload();
    assert!(
        status.starts_with("reload failed, still serving generation 2: ")
            && status.contains("/sites/0/routes/0/respond/body")
            && status.contains("unknown placeholder `{lang}`"),
        "the status names the failing value: {status}"
    );
    assert_eq!(conn.get("/").text(), "two");
    assert_eq!(
        proxy.client().get("/").text(),
        "two",
        "on a new connection too"
    );

    proxy.rewrite(json!([plain_site(
        json!([{ "respond": { "body": "three" } }])
    )]));
    assert_eq!(
        proxy.reload(),
        "serving generation 5",
        "a failed attempt uses up its generation number"
    );
    assert_eq!(conn.get("/").text(), "three");

    proxy.signal(libc::SIGTERM);
    assert_eq!(proxy.notification(), "STOPPING=1");
    let status = proxy.exit_within(PATIENCE).expect("the proxy exits");
    assert!(status.success(), "{status}");
}

#[test]
fn a_reload_adds_and_removes_listeners_while_other_connections_keep_working() {
    let sites = json!([plain_site(json!([{ "respond": { "body": "hi" } }]))]);
    let proxy = Proxy::start(sites.clone());
    let first = proxy.addr;
    let second = Reserved::new();
    let mut on_first = proxy.client();
    assert_eq!(on_first.get("/").text(), "hi");

    proxy.rewrite_with(
        sites.clone(),
        json!({ "listen": { "http": [first, second.addr], "https": [] } }),
    );
    assert_eq!(proxy.reload(), "serving generation 2");
    let mut on_second = Client::connect(second.addr);
    assert_eq!(on_second.get("/").text(), "hi", "the added listener serves");
    assert_eq!(
        on_first.get("/").text(),
        "hi",
        "a kept listener's connection"
    );

    proxy.rewrite_with(
        sites,
        json!({ "listen": { "http": [second.addr], "https": [] } }),
    );
    assert_eq!(proxy.reload(), "serving generation 3");
    assert!(refused(first), "the removed listener no longer accepts");
    assert_eq!(
        on_second.get("/").text(),
        "hi",
        "a connection of the kept listener keeps working"
    );
    assert_eq!(Client::connect(second.addr).get("/").text(), "hi");
}

#[test]
fn certificates_rotate_on_reload_and_a_broken_pair_keeps_the_last_good_one() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("fullchain.pem"), dir.path().join("key.pem"));
    let port = Reserved::new();
    let sites = json!([tls_site(
        port.addr,
        &cert,
        &key,
        false,
        json!([{ "respond": { "body": "tls" } }])
    )]);
    let proxy = Proxy::start(sites);

    let placeholder = served_chain(port.addr, HOST);
    assert_eq!(
        placeholder.len(),
        1,
        "a self-signed stand-in while the files are missing"
    );
    let reply = clients::h1_tls_get(port.addr, HOST, "/").unwrap();
    assert_eq!((reply.status, reply.text().as_str()), (200, "tls"));

    std::fs::write(&cert, fixture("kept.crt")).unwrap();
    std::fs::write(&key, fixture("kept.key")).unwrap();
    assert_eq!(proxy.reload(), "serving generation 2");
    let issued: Vec<String> = CertificateDer::pem_slice_iter(&fixture("kept.crt"))
        .map(|der| sha256(&der.unwrap()))
        .collect();
    assert_eq!(issued.len(), 2, "the fixture is a leaf and its issuer");
    assert_eq!(
        fingerprints(&served_chain(port.addr, HOST)),
        issued,
        "the issued chain replaces the stand-in at reload"
    );

    std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nnot base64\n").unwrap();
    assert_eq!(proxy.reload(), "serving generation 3");
    assert_eq!(
        fingerprints(&served_chain(port.addr, HOST)),
        issued,
        "a corrupt file at reload keeps the previous pair"
    );
    std::fs::remove_file(&key).unwrap();
    assert_eq!(proxy.reload(), "serving generation 4");
    assert_eq!(
        fingerprints(&served_chain(port.addr, HOST)),
        issued,
        "so does a missing one"
    );

    let renewed = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
    std::fs::write(&cert, pem("CERTIFICATE", renewed.cert.der())).unwrap();
    std::fs::write(
        &key,
        pem("PRIVATE KEY", &renewed.signing_key.serialize_der()),
    )
    .unwrap();
    assert_eq!(proxy.reload(), "serving generation 5");
    assert_eq!(
        fingerprints(&served_chain(port.addr, HOST)),
        [sha256(renewed.cert.der())],
        "a renewed pair is served after the reload"
    );
    let reply = clients::h1_tls_get(port.addr, HOST, "/").unwrap();
    assert_eq!((reply.status, reply.text().as_str()), (200, "tls"));
}

#[test]
fn a_tls_handshake_is_bounded_by_the_header_timeout() {
    let port = Reserved::new();
    let dir = tempfile::tempdir().unwrap();
    let sites = json!([tls_site(
        port.addr,
        &dir.path().join("c"),
        &dir.path().join("k"),
        false,
        json!([{ "respond": { "body": "tls" } }])
    )]);
    let top = json!({ "timeouts": { "header": "500ms", "shutdown": "1s" } });
    let _proxy = Proxy::start_with(sites, top);
    let mut silent = TcpStream::connect(port.addr).unwrap();
    silent.set_read_timeout(Some(PATIENCE)).unwrap();
    let started = Instant::now();
    let mut rest = Vec::new();
    let _ = std::io::Read::read_to_end(&mut silent, &mut rest);
    let waited = started.elapsed();
    assert!(
        rest.is_empty() && waited >= Duration::from_millis(400) && waited < Duration::from_secs(5),
        "a client that never sends a ClientHello is dropped after the header timeout: {waited:?}"
    );
}

/// The proxy with a TLS site (HTTP/1.1, HTTP/2 and HTTP/3 on one port) and a cleartext site,
/// both proxying to `origin`.
struct Mixed {
    proxy: Proxy,
    tls: Reserved,
    dir: tempfile::TempDir,
}

impl Mixed {
    fn start(routes: Value, shutdown: &str) -> Mixed {
        let dir = tempfile::tempdir().unwrap();
        let tls = reserve_udp();
        let sites = Mixed::sites(&dir, tls.addr, routes);
        let proxy = Proxy::start_with(sites, json!({ "timeouts": { "shutdown": shutdown } }));
        Mixed { proxy, tls, dir }
    }

    fn sites(dir: &tempfile::TempDir, tls: SocketAddr, routes: Value) -> Value {
        json!([
            plain_site(routes.clone()),
            tls_site(
                tls,
                &dir.path().join("c"),
                &dir.path().join("k"),
                true,
                routes
            ),
        ])
    }

    fn rewrite(&self, routes: Value) {
        self.proxy
            .rewrite(Mixed::sites(&self.dir, self.tls.addr, routes));
    }
}

/// An origin whose `/slow` answers once `release` opens, after counting the request in
/// `reached`; every other path answers at once with the path.
fn slow_origin(reached: Arc<AtomicUsize>, release: Gate) -> Origin {
    Origin::answering(move |request| {
        let target = request
            .line()
            .split(' ')
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        if target.starts_with("/slow") {
            reached.fetch_add(1, Ordering::SeqCst);
            if !release.wait(PATIENCE) {
                return Vec::new();
            }
            return ok("finished");
        }
        ok(&target)
    })
}

/// What a SIGTERM with slow requests in flight led to.
struct Stopped {
    /// From the signal to the proxy's exit.
    exited: Duration,
    status: std::process::ExitStatus,
    /// From the signal to the moment every client had its outcome.
    settled: Duration,
    /// HTTP/1.1, HTTP/1.1 over TLS, HTTP/2, HTTP/3.
    outcomes: [Result<Reply, String>; 4],
}

/// A slow request on each of HTTP/1.1 (cleartext and TLS), HTTP/2 and HTTP/3, in flight when
/// SIGTERM arrives; the origin answers them `release_after` the signal, or never.
fn sigterm_with_slow_requests(shutdown: &str, release_after: Option<Duration>) -> Stopped {
    let reached = Arc::new(AtomicUsize::new(0));
    let release = Gate::default();
    let origin = slow_origin(reached.clone(), release.clone());
    let mut mixed = Mixed::start(json!([{ "proxy": origin.url() }]), shutdown);
    let (tls, plain) = (mixed.tls.addr, mixed.proxy.addr);
    let rt = multi_thread_runtime();

    let h1_plain = std::thread::spawn(move || {
        let mut conn = h1_connect(plain)?;
        h1_get(&mut conn, "/slow", false)
    });
    let h1_tls = std::thread::spawn(move || {
        clients::h1_tls_get(tls, HOST, "/slow").map_err(|e| e.to_string())
    });
    let h2 = rt.spawn(async move {
        let mut h2 = H2::connect(tls, HOST).await.map_err(|e| e.to_string())?;
        let reply = h2.get("/slow").await.map_err(|e| e.to_string());
        drop(h2.send);
        let _ = tokio::time::timeout(PATIENCE, h2.done).await;
        reply
    });
    let h3 = rt.spawn(async move {
        let mut h3 = H3::connect(tls, HOST).await?;
        h3.get("/slow").await
    });
    support::eventually("every slow request reached the origin", || {
        reached.load(Ordering::SeqCst) == 4
    });

    let signalled = Instant::now();
    mixed.proxy.signal(libc::SIGTERM);
    assert_eq!(mixed.proxy.notification(), "STOPPING=1");
    support::eventually("the listeners close at once", || {
        refused(plain) && refused(tls)
    });
    if let Some(after) = release_after {
        std::thread::sleep(after);
        assert!(
            mixed.proxy.exit_within(Duration::ZERO).is_none(),
            "the proxy waits for its requests in flight"
        );
        release.open();
    }
    let status = mixed.proxy.exit_within(PATIENCE).expect("the proxy exits");
    let exited = signalled.elapsed();
    release.open();
    let outcomes = [
        h1_plain.join().unwrap(),
        h1_tls.join().unwrap(),
        rt.block_on(h2).unwrap(),
        rt.block_on(h3).unwrap(),
    ];
    Stopped {
        exited,
        status,
        settled: signalled.elapsed(),
        outcomes,
    }
}

#[test]
fn sigterm_finishes_requests_in_flight_on_every_protocol_and_exits_0() {
    let Stopped {
        exited,
        status,
        outcomes,
        ..
    } = sigterm_with_slow_requests("10s", Some(Duration::from_millis(500)));
    assert!(status.success(), "{status}");
    for (protocol, outcome) in ["h1", "h1 over TLS", "h2", "h3"].iter().zip(outcomes) {
        let reply = outcome.unwrap_or_else(|e| panic!("{protocol}: {e}"));
        assert_eq!(
            (reply.status, reply.text().as_str()),
            (200, "finished"),
            "{protocol}"
        );
    }
    assert!(
        exited >= Duration::from_millis(500) && exited < Duration::from_secs(10),
        "exits once the last request finished, inside the deadline: {exited:?}"
    );
}

#[test]
fn sigterm_cuts_what_is_still_running_at_the_shutdown_deadline_and_exits_0() {
    let Stopped {
        exited,
        status,
        settled,
        outcomes,
    } = sigterm_with_slow_requests("1s", None);
    assert!(status.success(), "{status}");
    assert!(
        exited >= Duration::from_millis(900) && exited < Duration::from_secs(4),
        "exits at the deadline: {exited:?}"
    );
    assert!(
        settled < Duration::from_secs(4),
        "every client learns of the cut at once, not at its idle timeout: {settled:?}"
    );
    for (protocol, outcome) in ["h1", "h1 over TLS", "h2", "h3"].iter().zip(outcomes) {
        assert!(
            outcome.is_err(),
            "{protocol}: a request cut at the deadline does not look complete: {outcome:?}"
        );
    }
}

#[test]
fn a_tls_handshake_under_way_when_sigterm_arrives_gets_its_request_answered() {
    let dir = tempfile::tempdir().unwrap();
    let port = Reserved::new();
    let sites = json!([tls_site(
        port.addr,
        &dir.path().join("c"),
        &dir.path().join("k"),
        false,
        json!([{ "respond": { "body": "answered" } }])
    )]);
    let mut proxy = Proxy::start(sites);
    let name = rustls::pki_types::ServerName::try_from(HOST).unwrap();
    let mut tls =
        rustls::ClientConnection::new(clients::client_config(&[b"http/1.1"]), name).unwrap();
    let mut sock = TcpStream::connect(port.addr).unwrap();
    sock.set_read_timeout(Some(PATIENCE)).unwrap();
    tls.write_tls(&mut sock).unwrap();
    while tls.is_handshaking() && !tls.wants_write() {
        tls.read_tls(&mut sock).unwrap();
        tls.process_new_packets().unwrap();
    }

    proxy.signal(libc::SIGTERM);
    assert_eq!(proxy.notification(), "STOPPING=1");
    std::thread::sleep(Duration::from_millis(100));
    std::io::Write::write_all(
        &mut tls.writer(),
        format!("GET / HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut flight = Vec::new();
    while tls.wants_write() {
        tls.write_tls(&mut flight).unwrap();
    }
    std::io::Write::write_all(&mut sock, &flight).unwrap();
    let reply = clients::read_h1_response(&mut rustls::Stream::new(&mut tls, &mut sock))
        .expect("the request that finished the handshake is answered");
    assert_eq!((reply.status, reply.text().as_str()), (200, "answered"));
    let status = proxy.exit_within(PATIENCE).expect("the proxy exits");
    assert!(status.success(), "{status}");
}

fn h1_connect(addr: SocketAddr) -> Result<TcpStream, String> {
    let conn = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    conn.set_read_timeout(Some(PATIENCE)).unwrap();
    Ok(conn)
}

/// One `GET` on a cleartext HTTP/1.1 connection; errors are values, for clients that count
/// them.
fn h1_get(conn: &mut TcpStream, path: &str, close: bool) -> Result<Reply, String> {
    let close = if close { "Connection: close\r\n" } else { "" };
    let request = format!("GET {path} HTTP/1.1\r\nHost: plain\r\n{close}\r\n");
    std::io::Write::write_all(conn, request.as_bytes()).map_err(|e| e.to_string())?;
    clients::read_h1_response(conn).map_err(|e| e.to_string())
}

/// Counts of one client kind: requests answered, and failures with their first message.
#[derive(Default)]
struct Tally {
    ok: AtomicUsize,
    failed: Mutex<Vec<String>>,
}

impl Tally {
    fn record(&self, what: &str, outcome: Result<Reply, String>) {
        match outcome {
            Ok(reply) if reply.status == 200 && reply.text().starts_with('/') => {
                self.ok.fetch_add(1, Ordering::Relaxed);
            }
            Ok(reply) => self.failed.lock().unwrap().push(format!(
                "{what}: {} {}",
                reply.status,
                reply.text()
            )),
            Err(e) => self.failed.lock().unwrap().push(format!("{what}: {e}")),
        }
    }
}

#[test]
fn fifty_reloads_under_mixed_h1_h2_h3_load_fail_no_request() {
    const RELOADS: u64 = 50;
    let origin = Origin::answering(|request| {
        let target = request.line().split(' ').nth(1).unwrap_or_default();
        ok(target)
    });
    let routes = |generation: u64| {
        json!([
            { "when": { "path": "/local" }, "respond": { "body": format!("/local {generation}") } },
            { "proxy": origin.url() },
        ])
    };
    let mixed = Mixed::start(routes(1), "5s");
    let (tls, plain) = (mixed.tls.addr, mixed.proxy.addr);
    let stop = Arc::new(AtomicBool::new(false));
    let kinds = [
        "h1 keep-alive",
        "h1 new connection",
        "h1 TLS new connection",
        "h2 streams",
        "h2 new connection",
        "h3 streams",
        "h3 new connection",
    ];
    let tallies: Arc<Vec<Tally>> = Arc::new(kinds.iter().map(|_| Tally::default()).collect());
    let path = |n: usize| {
        if n.is_multiple_of(2) {
            "/local"
        } else {
            "/proxied"
        }
    };

    let mut threads = Vec::new();
    for _ in 0..2 {
        let (stop, tallies) = (stop.clone(), tallies.clone());
        threads.push(std::thread::spawn(move || {
            let mut conn = h1_connect(plain).unwrap();
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let outcome = h1_get(&mut conn, path(n), false);
                let failed = outcome.is_err();
                tallies[0].record(kinds[0], outcome);
                if failed {
                    match h1_connect(plain) {
                        Ok(fresh) => conn = fresh,
                        Err(e) => tallies[0].record(kinds[0], Err(e)),
                    }
                }
            }
        }));
    }
    {
        let (stop, tallies) = (stop.clone(), tallies.clone());
        threads.push(std::thread::spawn(move || {
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let outcome =
                    h1_connect(plain).and_then(|mut conn| h1_get(&mut conn, path(n), true));
                tallies[1].record(kinds[1], outcome);
            }
        }));
    }
    {
        let (stop, tallies) = (stop.clone(), tallies.clone());
        threads.push(std::thread::spawn(move || {
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let outcome = clients::h1_tls_get(tls, HOST, path(n)).map_err(|e| e.to_string());
                tallies[2].record(kinds[2], outcome);
            }
        }));
    }

    let rt = multi_thread_runtime();
    let mut tasks = Vec::new();
    let h2 = Arc::new(tokio::sync::Mutex::new(
        rt.block_on(H2::connect(tls, HOST)).unwrap(),
    ));
    for task in 0..8 {
        let (stop, tallies, h2) = (stop.clone(), tallies.clone(), h2.clone());
        tasks.push(rt.spawn(async move {
            let mut n = task;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let pending = h2.lock().await.start_get(path(n)).await;
                let outcome = match pending {
                    Ok(response) => response.await.map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                tallies[3].record(kinds[3], outcome);
            }
        }));
    }
    {
        let (stop, tallies) = (stop.clone(), tallies.clone());
        tasks.push(rt.spawn(async move {
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let outcome = async {
                    let mut h2 = H2::connect(tls, HOST).await.map_err(|e| e.to_string())?;
                    h2.get(path(n)).await.map_err(|e| e.to_string())
                }
                .await;
                tallies[4].record(kinds[4], outcome);
            }
        }));
    }
    let h3 = Arc::new(tokio::sync::Mutex::new(
        rt.block_on(H3::connect(tls, HOST)).unwrap(),
    ));
    for task in 0..8 {
        let (stop, tallies, h3) = (stop.clone(), tallies.clone(), h3.clone());
        tasks.push(rt.spawn(async move {
            let mut n = task;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let pending = h3.lock().await.start_get(path(n)).await;
                let outcome = match pending {
                    Ok(response) => response.await,
                    Err(e) => Err(e),
                };
                tallies[5].record(kinds[5], outcome);
            }
        }));
    }
    {
        let (stop, tallies) = (stop.clone(), tallies.clone());
        tasks.push(rt.spawn(async move {
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                let outcome = async {
                    let mut h3 = H3::connect(tls, HOST).await?;
                    let reply = h3.get(path(n)).await;
                    h3.endpoint.close(quinn::VarInt::from_u32(0), b"");
                    reply
                }
                .await;
                tallies[6].record(kinds[6], outcome);
            }
        }));
    }

    support::eventually("every client kind got an answer", || {
        tallies.iter().all(|t| t.ok.load(Ordering::Relaxed) > 0)
    });
    let started = Instant::now();
    for generation in 2..=RELOADS + 1 {
        mixed.rewrite(routes(generation));
        assert_eq!(
            mixed.proxy.reload(),
            format!("serving generation {generation}")
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let reloading = started.elapsed();
    let reply = rt
        .block_on(async { h3.lock().await.get("/local").await })
        .unwrap();
    assert_eq!(
        reply.text(),
        format!("/local {}", RELOADS + 1),
        "the last generation serves"
    );
    stop.store(true, Ordering::Relaxed);
    for thread in threads {
        thread.join().unwrap();
    }
    for task in tasks {
        rt.block_on(task).unwrap();
    }

    let mut report = Vec::new();
    for (kind, tally) in kinds.iter().zip(tallies.iter()) {
        let failed = tally.failed.lock().unwrap();
        report.push(format!(
            "{kind}: {} ok, {} failed",
            tally.ok.load(Ordering::Relaxed),
            failed.len()
        ));
        assert!(
            failed.is_empty(),
            "{kind}: {:?}",
            &failed[..failed.len().min(5)]
        );
    }
    println!("{RELOADS} reloads in {reloading:?}: {}", report.join("; "));
}
