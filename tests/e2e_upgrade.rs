//! A SIGHUP that finds another program file at the path the proxy was started from hands the
//! listening sockets over to a process of that file: observed through the `NOTIFY_SOCKET`
//! protocol, the two processes, and what clients get over HTTP/1.1, HTTP/2 and HTTP/3 while it
//! happens.

#![cfg(target_os = "linux")]

mod support;

use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use support::clients::{self, H2, H3, Reply, reserve_udp};
use support::{Client, Origin, PATIENCE, Proxy, Reserved, ok};

const HOST: &str = "upgraded.test";

/// The program file a proxy is started from, in a directory of its own, so that another file
/// can take its place.
struct Program {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl Program {
    fn install() -> Program {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upstreamer");
        std::fs::copy(env!("CARGO_BIN_EXE_upstreamer"), &path).unwrap();
        Program { path, _dir: dir }
    }

    /// Puts another copy of the program at the path: a different file with the same content.
    fn replace(&self) {
        let next = self.path.with_extension("next");
        std::fs::copy(env!("CARGO_BIN_EXE_upstreamer"), &next).unwrap();
        std::fs::rename(next, &self.path).unwrap();
    }

    /// Puts a file with `content` and `mode` at the path.
    fn replace_with(&self, content: &str, mode: u32) {
        let next = self.path.with_extension("next");
        std::fs::write(&next, content).unwrap();
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::rename(next, &self.path).unwrap();
    }
}

/// A cleartext site for every host on the proxy's own port and a TLS site for [`HOST`] on
/// `tls` (TCP and QUIC), both made of `routes`.
fn sites(dir: &tempfile::TempDir, tls: SocketAddr, routes: Value) -> Value {
    json!([
        { "name": "plain", "hosts": ["*"], "routes": routes.clone() },
        {
            "name": "tls",
            "hosts": [HOST],
            "listen": [tls],
            "tls": {
                "cert": dir.path().join("c"),
                "key": dir.path().join("k"),
                "redirectHttp": false,
                "http3": true,
            },
            "routes": routes,
        },
    ])
}

/// `/local` answers `/local <generation>` from the proxy; every other path is proxied to
/// `origin`.
fn routes(origin: &Origin, generation: u64) -> Value {
    json!([
        { "when": { "path": "/local" }, "respond": { "body": format!("/local {generation}") } },
        { "proxy": origin.url() },
    ])
}

/// An origin that answers every request with its path.
fn echo_origin() -> Origin {
    Origin::answering(|request| ok(request.line().split(' ').nth(1).unwrap_or_default()))
}

/// Whether process `pid` runs: one that exited and awaits its parent does not.
fn runs(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| !stat.rsplit(')').next().unwrap_or("").starts_with(" Z"))
}

/// The program file process `pid` runs.
fn program_of(pid: u32) -> PathBuf {
    std::fs::read_link(format!("/proc/{pid}/exe")).unwrap()
}

/// Whether process `pid` reads a UDP socket bound to `port`: one is registered with an epoll
/// instance of the process. `/proc/net/udp` gives the sockets of the port by inode, and the
/// `fdinfo` of an epoll descriptor lists what it watches the same way.
fn reads_udp(pid: u32, port: u16) -> bool {
    let sockets = std::fs::read_to_string("/proc/net/udp").unwrap();
    let inodes: Vec<&str> = sockets
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.len() > 9 && fields[1].ends_with(&format!(":{port:04X}")))
        .map(|fields| fields[9])
        .collect();
    assert!(
        !inodes.is_empty(),
        "a UDP socket on port {port}:\n{sockets}"
    );
    let Ok(descriptors) = std::fs::read_dir(format!("/proc/{pid}/fdinfo")) else {
        return false;
    };
    // `tfd:        5 events:       1d data: ffffffffffffffff  pos:0 ino:61af sdev:7`
    let watched = |info: String| -> Vec<String> {
        let targets = info.lines().filter(|line| line.starts_with("tfd:"));
        let inodes = targets.filter_map(|line| line.split("ino:").nth(1)?.split(' ').next());
        inodes
            .filter_map(|inode| u64::from_str_radix(inode, 16).ok())
            .map(|inode| inode.to_string())
            .collect()
    };
    descriptors
        .filter_map(|entry| std::fs::read_to_string(entry.ok()?.path()).ok())
        .flat_map(watched)
        .any(|inode| inodes.contains(&inode.as_str()))
}

/// Reads the notifications of a handover that succeeds; returns the successor's process id.
fn handed_over(proxy: &Proxy) -> u32 {
    let reloading = proxy.notification();
    assert!(
        reloading.starts_with("RELOADING=1\nMONOTONIC_USEC="),
        "{reloading}"
    );
    let moved = proxy.notification();
    let pid: u32 = moved
        .strip_prefix("MAINPID=")
        .and_then(|rest| rest.strip_suffix("\nREADY=1"))
        .unwrap_or_else(|| panic!("the main process moves and the reload ends: {moved:?}"))
        .parse()
        .unwrap();
    assert_eq!(
        proxy.notification(),
        "READY=1\nSTATUS=serving generation 1",
        "the successor reports as a started process does, once it is the main one"
    );
    pid
}

/// Stops the successor (the process group gets the signal) and waits until it is gone.
fn stop_successor(proxy: &Proxy, pid: u32) {
    proxy.signal(libc::SIGTERM);
    support::eventually("the successor exits", || !runs(pid));
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

fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// One `GET` on a cleartext HTTP/1.1 connection. Returns the reply and whether the server
/// said it closes the connection.
fn h1_exchange(conn: &mut TcpStream, path: &str, close: bool) -> Result<(Reply, bool), String> {
    let close = if close { "Connection: close\r\n" } else { "" };
    let request = format!("GET {path} HTTP/1.1\r\nHost: plain\r\n{close}\r\n");
    conn.write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match conn.read(&mut chunk).map_err(|e| format!("read: {e}"))? {
            0 => return Err(format!("closed after {} bytes of a response", raw.len())),
            n => raw.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("not a status line: {head}"))?;
    let length: usize = support::header(&head, "content-length")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("no Content-Length: {head}"))?;
    let mut body = raw.split_off(end);
    while body.len() < length {
        match conn.read(&mut chunk).map_err(|e| format!("read: {e}"))? {
            0 => return Err("closed inside a body".to_owned()),
            n => body.extend_from_slice(&chunk[..n]),
        }
    }
    let closes = support::header(&head, "connection").is_some_and(|v| v == "close");
    Ok((Reply { status, body }, closes))
}

fn h1_connect(addr: SocketAddr) -> Result<TcpStream, String> {
    let conn = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    conn.set_read_timeout(Some(PATIENCE)).unwrap();
    conn.set_nodelay(true).unwrap();
    Ok(conn)
}

/// What one kind of client saw: requests answered, and every request that was not.
#[derive(Default)]
struct Tally {
    ok: AtomicUsize,
    failed: Mutex<Vec<String>>,
}

impl Tally {
    fn record(&self, outcome: Result<Reply, String>) {
        match outcome {
            Ok(reply) if reply.status == 200 && reply.text().starts_with('/') => {
                self.ok.fetch_add(1, Ordering::Relaxed);
            }
            Ok(reply) => {
                let failure = format!("{} {}", reply.status, reply.text());
                self.failed.lock().unwrap().push(failure);
            }
            Err(e) => self.failed.lock().unwrap().push(e),
        }
    }
}

/// The kinds of clients a [`Load`] runs, in the order of its tallies.
const KINDS: [&str; 7] = [
    "h1 keep-alive",
    "h1 new connection",
    "h1 TLS new connection",
    "h2 streams",
    "h2 new connection",
    "h3 streams",
    "h3 new connection",
];
/// The kinds over TCP: no request of theirs may fail.
const TCP_KINDS: std::ops::Range<usize> = 0..5;

/// Clients of every kind that send requests one after another until stopped. A client on a
/// kept connection follows what the server says about it: `Connection: close` and GOAWAY end
/// the connection, and its next request goes on a new one. No client sends a request again.
struct Load {
    stop: Arc<AtomicBool>,
    tallies: Arc<Vec<Tally>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    runtime: tokio::runtime::Runtime,
}

impl Load {
    fn start(plain: SocketAddr, tls: SocketAddr) -> Load {
        let stop = Arc::new(AtomicBool::new(false));
        let tallies: Arc<Vec<Tally>> = Arc::new(KINDS.iter().map(|_| Tally::default()).collect());
        let path = |n: usize| {
            if n.is_multiple_of(2) {
                "/local"
            } else {
                "/proxied"
            }
        };
        let mut threads = Vec::new();
        for _ in 0..4 {
            let (stop, tallies) = (stop.clone(), tallies.clone());
            threads.push(std::thread::spawn(move || {
                let mut kept: Option<TcpStream> = None;
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    let outcome =
                        kept.take()
                            .map_or_else(|| h1_connect(plain), Ok)
                            .and_then(|mut conn| {
                                let (reply, closes) = h1_exchange(&mut conn, path(n), false)?;
                                if !closes {
                                    kept = Some(conn);
                                }
                                Ok(reply)
                            });
                    tallies[0].record(outcome);
                }
            }));
        }
        {
            let (stop, tallies) = (stop.clone(), tallies.clone());
            threads.push(std::thread::spawn(move || {
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    let outcome = h1_connect(plain)
                        .and_then(|mut conn| h1_exchange(&mut conn, path(n), true))
                        .map(|(reply, _)| reply);
                    tallies[1].record(outcome);
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
                        clients::h1_tls_get(tls, HOST, path(n)).map_err(|e| e.to_string());
                    tallies[2].record(outcome);
                }
            }));
        }

        let runtime = multi_thread_runtime();
        let mut tasks = Vec::new();
        for task in 0..4 {
            let (stop, tallies) = (stop.clone(), tallies.clone());
            tasks.push(runtime.spawn(async move {
                let mut kept: Option<H2> = None;
                let mut n = task;
                while !stop.load(Ordering::Relaxed) {
                    let mut conn = match kept.take() {
                        Some(conn) => conn,
                        None => match H2::connect(tls, HOST).await {
                            Ok(conn) => conn,
                            Err(e) => {
                                tallies[3].record(Err(format!("connect: {e}")));
                                continue;
                            }
                        },
                    };
                    // A connection that takes no new stream (the server sent GOAWAY) is
                    // replaced; the request was not sent on it.
                    if let Ok(response) = conn.start_get(path(n)).await {
                        n += 1;
                        tallies[3].record(response.await.map_err(|e| e.to_string()));
                        kept = Some(conn);
                    }
                }
            }));
        }
        {
            let (stop, tallies) = (stop.clone(), tallies.clone());
            tasks.push(runtime.spawn(async move {
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    let outcome = async {
                        let mut h2 = H2::connect(tls, HOST)
                            .await
                            .map_err(|e| format!("connect: {e}"))?;
                        h2.get(path(n)).await.map_err(|e| e.to_string())
                    }
                    .await;
                    tallies[4].record(outcome);
                }
            }));
        }
        for task in 0..4 {
            let (stop, tallies) = (stop.clone(), tallies.clone());
            tasks.push(runtime.spawn(async move {
                let mut kept: Option<H3> = None;
                let mut n = task;
                while !stop.load(Ordering::Relaxed) {
                    let mut conn = match kept.take() {
                        Some(conn) => conn,
                        None => match H3::connect(tls, HOST).await {
                            Ok(conn) => conn,
                            Err(e) => {
                                tallies[5].record(Err(format!("connect: {e}")));
                                continue;
                            }
                        },
                    };
                    n += 1;
                    let outcome = match conn.start_get(path(n)).await {
                        Ok(response) => response.await,
                        Err(e) => Err(e),
                    };
                    if outcome.is_ok() {
                        kept = Some(conn);
                    }
                    tallies[5].record(outcome);
                }
            }));
        }
        {
            let (stop, tallies) = (stop.clone(), tallies.clone());
            tasks.push(runtime.spawn(async move {
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    let outcome = async {
                        let mut h3 = H3::connect(tls, HOST)
                            .await
                            .map_err(|e| format!("connect: {e}"))?;
                        h3.get(path(n)).await
                    };
                    let outcome = tokio::time::timeout(PATIENCE, outcome)
                        .await
                        .unwrap_or_else(|_| Err("no answer".to_owned()));
                    tallies[6].record(outcome);
                }
            }));
        }
        Load {
            stop,
            tallies,
            threads,
            tasks,
            runtime,
        }
    }

    /// Requests answered so far, per kind.
    fn answered(&self) -> Vec<usize> {
        let answered = self.tallies.iter().map(|t| t.ok.load(Ordering::Relaxed));
        answered.collect()
    }

    fn stop(self) -> Arc<Vec<Tally>> {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            thread.join().unwrap();
        }
        for task in self.tasks {
            self.runtime.block_on(task).unwrap();
        }
        self.tallies
    }
}

#[test]
fn a_replaced_program_takes_over_under_load_without_failing_a_request() {
    let origin = echo_origin();
    let program = Program::install();
    let dir = tempfile::tempdir().unwrap();
    let tls = reserve_udp();
    let top = json!({ "timeouts": { "shutdown": "4s" } });
    let mut proxy = Proxy::start_program(
        &program.path,
        sites(&dir, tls.addr, routes(&origin, 1)),
        top.clone(),
    );
    let old = proxy.pid();
    let mut idle = proxy.client();
    assert_eq!(idle.get("/local").text(), "/local 1");

    let load = Load::start(proxy.addr, tls.addr);
    support::eventually("every kind of client is answered", || {
        load.answered().iter().all(|&n| n >= 20)
    });

    program.replace();
    proxy.rewrite_with(sites(&dir, tls.addr, routes(&origin, 2)), top);
    proxy.signal(libc::SIGHUP);
    let new = handed_over(&proxy);
    let at_handover = load.answered();
    assert_ne!(new, old, "another process is the main one");
    assert!(runs(new));
    assert_eq!(
        program_of(new),
        program.path,
        "it runs the file at the path"
    );
    assert_ne!(program_of(old), program.path, "which the old one does not");

    let late = idle.get("/local");
    assert_eq!(
        (late.text().as_str(), late.header("connection")),
        ("/local 1", Some("close")),
        "a request on a connection kept from before is answered by the old process, which \
         then closes it"
    );
    assert!(idle.closed());
    let status = proxy.exit_within(PATIENCE).expect("the old process exits");
    assert!(status.success(), "{status}");

    support::eventually(
        "every kind of client is answered by the new process",
        || {
            let now = load.answered();
            now.iter()
                .zip(&at_handover)
                .all(|(now, then)| now >= &(then + 20))
        },
    );
    let tallies = load.stop();
    assert_eq!(proxy.client().get("/local").text(), "/local 2");
    for (kind, tally) in KINDS.iter().zip(tallies.iter()) {
        let failed = tally.failed.lock().unwrap();
        println!(
            "{kind}: {} answered, {} failed {:?}",
            tally.ok.load(Ordering::Relaxed),
            failed.len(),
            &failed[..failed.len().min(3)]
        );
    }
    for kind in TCP_KINDS {
        let failed = tallies[kind].failed.lock().unwrap();
        assert!(failed.is_empty(), "{}: {failed:?}", KINDS[kind]);
    }
    stop_successor(&proxy, new);
}

#[test]
fn requests_in_flight_finish_on_the_old_process_while_the_new_one_serves() {
    let reached = Arc::new(AtomicUsize::new(0));
    let release = Gate::default();
    let origin = slow_origin(reached.clone(), release.clone());
    let program = Program::install();
    let dir = tempfile::tempdir().unwrap();
    let tls = reserve_udp();
    let top = json!({ "timeouts": { "shutdown": "15s" } });
    let mut proxy = Proxy::start_program(
        &program.path,
        sites(&dir, tls.addr, json!([{ "proxy": origin.url() }])),
        top,
    );
    let (plain, tls) = (proxy.addr, tls.addr);
    let rt = multi_thread_runtime();

    let h1_plain = std::thread::spawn(move || {
        let mut conn = h1_connect(plain)?;
        h1_exchange(&mut conn, "/slow", false).map(|(reply, _)| reply)
    });
    let h1_tls = std::thread::spawn(move || {
        clients::h1_tls_get(tls, HOST, "/slow").map_err(|e| e.to_string())
    });
    let h2 = rt.spawn(async move {
        let mut h2 = H2::connect(tls, HOST).await.map_err(|e| e.to_string())?;
        h2.get("/slow").await.map_err(|e| e.to_string())
    });
    let h3 = rt.spawn(async move {
        let mut h3 = H3::connect(tls, HOST).await?;
        h3.get("/slow").await
    });
    support::eventually("every slow request reached the origin", || {
        reached.load(Ordering::SeqCst) == 4
    });

    program.replace();
    proxy.signal(libc::SIGHUP);
    let new = handed_over(&proxy);
    assert_ne!(new, proxy.pid());

    let (reply, _) = h1_exchange(&mut h1_connect(plain).unwrap(), "/fast", true).unwrap();
    assert_eq!((reply.status, reply.text().as_str()), (200, "/fast"));
    let reply = clients::h1_tls_get(tls, HOST, "/fast").unwrap();
    assert_eq!((reply.status, reply.text().as_str()), (200, "/fast"));
    let reply = rt
        .block_on(async {
            H2::connect(tls, HOST)
                .await?
                .get("/fast")
                .await
                .map_err(std::io::Error::other)
        })
        .unwrap();
    assert_eq!((reply.status, reply.text().as_str()), (200, "/fast"));
    assert!(
        proxy.exit_within(Duration::ZERO).is_none(),
        "the old process waits for its requests in flight"
    );

    // The old process reads the UDP sockets while it has a QUIC connection, so a handshake
    // begun now is answered once it lets go.
    assert!(
        reads_udp(proxy.pid(), tls.port()) && !reads_udp(new, tls.port()),
        "a datagram has one reader: the process whose QUIC connections it may belong to"
    );
    let asked = Instant::now();
    let h3_new = rt.spawn(async move {
        let mut h3 = H3::connect(tls, HOST).await?;
        h3.get("/fast").await
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !h3_new.is_finished(),
        "no process answers a new QUIC connection while the old one has one open"
    );

    release.open();
    let outcomes = [
        h1_plain.join().unwrap(),
        h1_tls.join().unwrap(),
        rt.block_on(h2).unwrap(),
        rt.block_on(h3).unwrap(),
    ];
    for (protocol, outcome) in ["h1", "h1 over TLS", "h2", "h3"].iter().zip(outcomes) {
        let reply = outcome.unwrap_or_else(|e| panic!("{protocol}: {e}"));
        assert_eq!(
            (reply.status, reply.text().as_str()),
            (200, "finished"),
            "{protocol}"
        );
    }
    let reply = rt
        .block_on(h3_new)
        .unwrap()
        .expect("the handshake begun during the handover completes on the new process");
    assert_eq!((reply.status, reply.text().as_str()), (200, "/fast"));
    println!(
        "a QUIC connection begun while the old process still had one was answered after {:?}",
        asked.elapsed()
    );
    let status = proxy.exit_within(PATIENCE).expect("the old process exits");
    assert!(status.success(), "{status}");
    assert!(
        reads_udp(new, tls.port()),
        "the new process took the UDP sockets"
    );
    stop_successor(&proxy, new);
}

#[test]
fn a_second_handover_leaves_the_udp_sockets_with_the_first_process_until_it_lets_go() {
    let reached = Arc::new(AtomicUsize::new(0));
    let release = Gate::default();
    let origin = slow_origin(reached.clone(), release.clone());
    let program = Program::install();
    let dir = tempfile::tempdir().unwrap();
    let tls = reserve_udp();
    let top = json!({ "timeouts": { "shutdown": "15s" } });
    let mut proxy = Proxy::start_program(
        &program.path,
        sites(&dir, tls.addr, json!([{ "proxy": origin.url() }])),
        top,
    );
    let (first, tls) = (proxy.pid(), tls.addr);
    let rt = multi_thread_runtime();
    let slow = rt.spawn(async move {
        let mut h3 = H3::connect(tls, HOST).await?;
        h3.get("/slow").await
    });
    support::eventually("the slow request reached the origin", || {
        reached.load(Ordering::SeqCst) == 1
    });

    program.replace();
    proxy.signal(libc::SIGHUP);
    let second = handed_over(&proxy);
    program.replace();
    proxy.signal(libc::SIGHUP);
    let third = handed_over(&proxy);
    assert!(second != first && third != second && runs(third));
    let reply = clients::h1_tls_get(tls, HOST, "/fast").unwrap();
    assert_eq!((reply.status, reply.text().as_str()), (200, "/fast"));
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        reads_udp(first, tls.port())
            && !reads_udp(second, tls.port())
            && !reads_udp(third, tls.port()),
        "the process with the QUIC connection is the one reader, two handovers later"
    );

    release.open();
    let reply = rt
        .block_on(slow)
        .unwrap()
        .expect("the request in flight finishes");
    assert_eq!((reply.status, reply.text().as_str()), (200, "finished"));
    let status = proxy
        .exit_within(PATIENCE)
        .expect("the first process exits");
    assert!(status.success(), "{status}");
    support::eventually("the last process reads the UDP sockets", || {
        reads_udp(third, tls.port())
    });
    support::eventually("the process in between is gone", || !runs(second));
    let reply = rt
        .block_on(async { H3::connect(tls, HOST).await?.get("/fast").await })
        .expect("HTTP/3 on the last process");
    assert_eq!((reply.status, reply.text().as_str()), (200, "/fast"));
    stop_successor(&proxy, third);
}

#[test]
fn a_program_that_cannot_take_over_leaves_the_running_one_serving() {
    let plain = |body: &str| json!([{ "name": "plain", "hosts": ["*"], "routes": [{ "respond": { "body": body } }] }]);
    let program = Program::install();
    let mut proxy = Proxy::start_program(&program.path, plain("one"), json!({}));
    let mut kept = proxy.client();
    assert_eq!(kept.get("/").text(), "one");

    proxy.rewrite(plain("two"));
    assert_eq!(
        proxy.reload(),
        "serving generation 2",
        "the same file at the path: the config is reloaded in the process"
    );

    let still_serving = |proxy: &mut Proxy, kept: &mut Client| {
        let reply = kept.get("/");
        assert_eq!(
            (reply.text().as_str(), reply.header("connection")),
            ("two", None),
            "a kept connection goes on"
        );
        assert_eq!(proxy.client().get("/").text(), "two", "and so do new ones");
        assert!(proxy.exit_within(Duration::ZERO).is_none());
    };
    let refused = format!(
        "reload failed, still serving generation 2: cannot hand over to {}: ",
        program.path.display()
    );

    proxy.rewrite(plain("three"));
    program.replace_with("#!/bin/sh\nexit 1\n", 0o755);
    assert_eq!(
        proxy.reload(),
        format!("{refused}it exited before it was ready")
    );
    still_serving(&mut proxy, &mut kept);

    program.replace_with("#!/bin/sh\nexit 1\n", 0o644);
    let status = proxy.reload();
    assert!(
        status.starts_with(&format!("{refused}cannot start it: ")),
        "{status}"
    );
    still_serving(&mut proxy, &mut kept);

    program.replace();
    proxy.rewrite(plain("{lang}"));
    let status = proxy.reload();
    assert!(
        status.starts_with(&refused)
            && status.contains("/sites/0/routes/0/respond/body")
            && status.contains("unknown placeholder `{lang}`"),
        "the new process says what is wrong with the config: {status}"
    );
    still_serving(&mut proxy, &mut kept);

    proxy.rewrite(plain("three"));
    proxy.signal(libc::SIGHUP);
    let new = handed_over(&proxy);
    assert_eq!(proxy.client().get("/").text(), "three");
    let status = proxy.exit_within(PATIENCE).expect("the old process exits");
    assert!(status.success(), "{status}");
    stop_successor(&proxy, new);
}

/// One `GET /` over TLS on a connection of its own, with `config`'s sessions; says whether the
/// handshake resumed one.
fn tls_get(config: &Arc<rustls::ClientConfig>, addr: SocketAddr) -> (Reply, rustls::HandshakeKind) {
    let name = rustls::pki_types::ServerName::try_from(HOST).unwrap();
    let mut tls = rustls::ClientConnection::new(config.clone(), name).unwrap();
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(PATIENCE)).unwrap();
    while tls.is_handshaking() {
        tls.complete_io(&mut sock).unwrap();
    }
    let kind = tls.handshake_kind().unwrap();
    let mut io = clients::TlsStream { sock, tls };
    io.write_all(format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n").as_bytes())
        .unwrap();
    io.flush().unwrap();
    (clients::read_h1_response(&mut io).unwrap(), kind)
}

#[test]
fn a_tls_session_of_the_old_process_resumes_on_the_new_one() {
    let program = Program::install();
    let dir = tempfile::tempdir().unwrap();
    let port = Reserved::new();
    let site = json!([{
        "name": "tls",
        "hosts": [HOST],
        "listen": [port.addr],
        "tls": {
            "cert": dir.path().join("c"),
            "key": dir.path().join("k"),
            "redirectHttp": false,
            "http3": false,
        },
        "routes": [{ "respond": { "body": "tls" } }],
    }]);
    let mut proxy = Proxy::start_program(&program.path, site, json!({}));
    let config = clients::client_config(&[b"http/1.1"]);
    assert_eq!(tls_get(&config, port.addr).1, rustls::HandshakeKind::Full);
    assert_eq!(
        tls_get(&config, port.addr).1,
        rustls::HandshakeKind::Resumed,
        "the client resumes sessions at all"
    );

    program.replace();
    proxy.signal(libc::SIGHUP);
    let new = handed_over(&proxy);
    let (reply, kind) = tls_get(&config, port.addr);
    assert_eq!((reply.status, reply.text().as_str()), (200, "tls"));
    assert_eq!(
        kind,
        rustls::HandshakeKind::Resumed,
        "the new process decrypts a ticket the old one issued"
    );
    let status = proxy.exit_within(PATIENCE).expect("the old process exits");
    assert!(status.success(), "{status}");
    stop_successor(&proxy, new);
}

#[test]
fn a_stop_during_a_handover_stops_both_processes() {
    let reached = Arc::new(AtomicUsize::new(0));
    let release = Gate::default();
    let origin = slow_origin(reached.clone(), release.clone());
    let program = Program::install();
    let routes = json!([{ "proxy": origin.url() }]);
    let site = json!([{ "name": "plain", "hosts": ["*"], "routes": routes }]);
    let top = json!({ "timeouts": { "shutdown": "15s" } });
    let mut proxy = Proxy::start_program(&program.path, site, top);
    let plain = proxy.addr;
    let slow = std::thread::spawn(move || {
        let mut conn = h1_connect(plain)?;
        h1_exchange(&mut conn, "/slow", false).map(|(reply, _)| reply)
    });
    support::eventually("the slow request reached the origin", || {
        reached.load(Ordering::SeqCst) == 1
    });

    program.replace();
    proxy.signal(libc::SIGHUP);
    let new = handed_over(&proxy);
    assert!(proxy.exit_within(Duration::ZERO).is_none() && runs(new));

    proxy.signal(libc::SIGTERM);
    assert_eq!(
        proxy.notification(),
        "STOPPING=1",
        "the main process says it stops"
    );
    support::eventually(
        "the new process, which has nothing in flight, exits",
        || !runs(new),
    );
    assert!(
        proxy.exit_within(Duration::from_millis(200)).is_none(),
        "the old process still waits for its request"
    );
    release.open();
    let reply = slow.join().unwrap().unwrap();
    assert_eq!((reply.status, reply.text().as_str()), (200, "finished"));
    let status = proxy.exit_within(PATIENCE).expect("the old process exits");
    assert!(status.success(), "{status}");
}
