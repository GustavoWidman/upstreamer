//! HTTP/3 through the real binary: curl (when it is built with HTTP/3) and an h3 client on
//! quinn, against TLS sites whose certificate files do not exist, so the proxy answers with a
//! self-signed certificate per name and the clients accept any certificate.

mod support;

use bytes::{Buf, Bytes};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use support::{Origin, Proxy, Reserved, ok, payload, sha256};

const HOST: &str = "h3.test";

/// A port free for TCP and UDP on loopback, held for TCP while the value lives.
fn reserve() -> Reserved {
    loop {
        let port = Reserved::new();
        if std::net::UdpSocket::bind(port.addr).is_ok() {
            return port;
        }
    }
}

/// A TLS site for `host` on `addr` with its own (missing) certificate files.
fn tls_site(host: &str, addr: SocketAddr, http3: bool, routes: Value) -> Value {
    json!({
        "name": host,
        "hosts": [host],
        "listen": [addr],
        "tls": {
            "cert": format!("/nonexistent/{host}.crt"),
            "key": format!("/nonexistent/{host}.key"),
            "redirectHttp": false,
            "http3": http3,
        },
        "routes": routes,
    })
}

/// The proxy serving one HTTP/3 site made of `routes`.
fn h3_proxy(routes: Value) -> (Proxy, Reserved) {
    let port = reserve();
    let proxy = Proxy::start(json!([tls_site(HOST, port.addr, true, routes)]));
    (proxy, port)
}

/// Serves 1 MiB on GET and answers any other request with the SHA-256 of its body.
fn transfer_origin(blob: Arc<Vec<u8>>) -> Origin {
    Origin::answering(move |request| {
        if request.line().starts_with("GET ") || request.line().starts_with("HEAD ") {
            let mut response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", blob.len()).into_bytes();
            if request.line().starts_with("GET ") {
                response.extend_from_slice(&blob);
            }
            return response;
        }
        let data = match request.header("transfer-encoding") {
            Some(_) => support::dechunk(&request.body),
            None => request.body.clone(),
        };
        ok(&sha256(&data))
    })
}

/// An h3 connection on a UDP socket of its own. Clones open their requests on the same
/// connection.
#[derive(Clone)]
struct H3 {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _endpoint: quinn::Endpoint,
    authority: String,
}

/// Resolves with the error that ended the connection.
type Closed = tokio::task::JoinHandle<h3::error::ConnectionError>;

struct Reply {
    status: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl H3 {
    async fn connect(addr: SocketAddr) -> H3 {
        H3::connect_watched(addr).await.0
    }

    async fn connect_watched(addr: SocketAddr) -> (H3, Closed) {
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let quic = endpoint.connect(addr, HOST).unwrap().await.unwrap();
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(quic))
            .await
            .unwrap();
        let closed =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
        let h3 = H3 {
            send,
            _endpoint: endpoint,
            authority: format!("{HOST}:{}", addr.port()),
        };
        (h3, closed)
    }

    async fn get(&mut self, path: &str) -> Reply {
        self.request("GET", path, &[], None).await.unwrap()
    }

    /// One request; `body` goes out in 64 KiB DATA frames.
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Reply, String> {
        let mut request = http::Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.authority));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(()).unwrap();
        let mut stream = self
            .send
            .send_request(request)
            .await
            .map_err(|e| e.to_string())?;
        for chunk in body.unwrap_or_default().chunks(64 * 1024) {
            stream
                .send_data(Bytes::copy_from_slice(chunk))
                .await
                .map_err(|e| e.to_string())?;
        }
        stream.finish().await.map_err(|e| e.to_string())?;
        let response = stream.recv_response().await.map_err(|e| e.to_string())?;
        let mut body = Vec::new();
        while let Some(mut data) = stream.recv_data().await.map_err(|e| e.to_string())? {
            body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        Ok(Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body,
        })
    }
}

#[derive(Debug)]
struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// curl with `args` against the site on `addr`; `None` (the test skips) when this curl has no
/// HTTP/3.
fn curl(addr: SocketAddr, args: &[&str]) -> Option<std::process::Output> {
    let version = support::curl(&["--version"])?;
    if !String::from_utf8_lossy(&version.stdout).contains("HTTP3") {
        eprintln!("skipped: curl is built without HTTP/3");
        return None;
    }
    let resolve = format!("{HOST}:{}:127.0.0.1", addr.port());
    let mut all = vec!["--insecure", "--resolve", &resolve];
    all.extend_from_slice(args);
    let output = support::curl(&all)?;
    assert!(
        output.status.success(),
        "curl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output)
}

fn url(addr: SocketAddr, path: &str) -> String {
    format!("https://{HOST}:{}{path}", addr.port())
}

#[test]
fn curl_gets_and_moves_a_megabyte_both_ways_over_h3() {
    let blob = Arc::new(payload(1 << 20));
    let origin = transfer_origin(blob.clone());
    let (_proxy, port) = h3_proxy(json!([
        { "when": { "path": "/hello" }, "respond": { "body": "hello" } },
        { "proxy": origin.url() },
    ]));
    let addr = port.addr;

    let Some(hello) = curl(addr, &["--http3-only", "-i", &url(addr, "/hello")]) else {
        return;
    };
    let hello = String::from_utf8_lossy(&hello.stdout).into_owned();
    assert!(hello.starts_with("HTTP/3 200"), "{hello}");
    assert!(hello.contains("content-length: 5\r\n"), "{hello}");
    assert!(hello.ends_with("\r\n\r\nhello"), "{hello}");

    let down = curl(addr, &["--http3-only", &url(addr, "/down")]).unwrap();
    assert_eq!(down.stdout.len(), blob.len(), "1 MiB down");
    assert_eq!(sha256(&down.stdout), sha256(&blob), "1 MiB down");

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blob");
    std::fs::write(&file, &*blob).unwrap();
    let data = format!("@{}", file.display());
    let up = curl(
        addr,
        &["--http3-only", "--data-binary", &data, &url(addr, "/up")],
    )
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&up.stdout),
        sha256(&blob),
        "1 MiB up"
    );

    let head = curl(addr, &["--http3-only", "--head", &url(addr, "/down")]).unwrap();
    let head = String::from_utf8_lossy(&head.stdout).into_owned();
    assert!(
        head.contains("content-length: 1048576\r\n"),
        "HEAD keeps the origin's length: {head}"
    );
}

#[test]
fn alt_svc_on_tls_responses_of_http3_sites_only() {
    let (on, off) = (reserve(), reserve());
    let _proxy = Proxy::start(json!([
        tls_site(
            HOST,
            on.addr,
            true,
            json!([{ "respond": { "body": "on" } }])
        ),
        tls_site(
            "off.test",
            off.addr,
            false,
            json!([{ "respond": { "body": "off" } }])
        ),
    ]));
    let Some(h1) = curl(on.addr, &["--http1.1", "--head", &url(on.addr, "/")]) else {
        return;
    };
    let h1 = String::from_utf8_lossy(&h1.stdout).into_owned();
    assert!(
        h1.contains(&format!(
            "alt-svc: h3=\":{}\"; ma=86400\r\n",
            on.addr.port()
        )),
        "{h1}"
    );

    let h3 = curl(on.addr, &["--http3-only", "--head", &url(on.addr, "/")]).unwrap();
    let h3 = String::from_utf8_lossy(&h3.stdout).into_owned();
    assert!(h3.starts_with("HTTP/3 200"), "{h3}");
    assert!(!h3.contains("alt-svc"), "not repeated over h3: {h3}");

    let resolve = format!("off.test:{}:127.0.0.1", off.addr.port());
    let target = format!("https://off.test:{}/", off.addr.port());
    let plain = support::curl(&[
        "--insecure",
        "--resolve",
        &resolve,
        "--http1.1",
        "--head",
        &target,
    ])
    .unwrap();
    let plain = String::from_utf8_lossy(&plain.stdout).into_owned();
    assert!(plain.starts_with("HTTP/1.1 200"), "{plain}");
    assert!(!plain.contains("alt-svc"), "a site with http3 off: {plain}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_megabyte_streams_both_ways_with_and_without_a_length() {
    let blob = Arc::new(payload(1 << 20));
    let origin = transfer_origin(blob.clone());
    let (_proxy, port) = h3_proxy(json!([{ "proxy": origin.url() }]));
    let mut h3 = H3::connect(port.addr).await;

    let down = h3.get("/down").await;
    assert_eq!(down.status, 200);
    assert_eq!(down.headers["content-length"], "1048576");
    assert_eq!(sha256(&down.body), sha256(&blob), "1 MiB down");

    let length = blob.len().to_string();
    let up = h3
        .request("POST", "/up", &[("content-length", &length)], Some(&blob))
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&up.body),
        sha256(&blob),
        "with a length"
    );

    let up = h3.request("POST", "/up", &[], Some(&blob)).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&up.body),
        sha256(&blob),
        "without a length, chunked to the origin"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_that_breaks_its_content_length_is_not_forwarded_whole() {
    let complete = Arc::new(AtomicUsize::new(0));
    let origin = Origin::answering({
        let complete = complete.clone();
        move |_| {
            complete.fetch_add(1, Ordering::SeqCst);
            ok("got it")
        }
    });
    let (_proxy, port) = h3_proxy(json!([{ "proxy": origin.url() }]));
    let mut h3 = H3::connect(port.addr).await;
    for (declared, sent) in [("10", &b"short"[..]), ("2", &b"too long"[..])] {
        let reply = h3
            .request("POST", "/", &[("content-length", declared)], Some(sent))
            .await
            .unwrap();
        assert!(
            reply.status >= 400,
            "content-length {declared} with {} bytes: {}",
            sent.len(),
            reply.status
        );
    }
    let reply = h3
        .request("POST", "/", &[("content-length", "3")], None)
        .await
        .unwrap();
    assert_eq!(reply.status, 400, "a declared body that never came");
    assert_eq!(complete.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_arrive_one_by_one() {
    let (got_first, first_seen) = mpsc::channel::<()>();
    let first_seen = Arc::new(Mutex::new(first_seen));
    let origin = Origin::start(move |stream, _| {
        let mut conn = support::Client::over(stream);
        conn.request().unwrap();
        conn.send(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n\
              d\r\ndata: first\n\n\r\n",
        )
        .unwrap();
        first_seen
            .lock()
            .unwrap()
            .recv_timeout(support::PATIENCE)
            .expect("the client saw the first event before the second was sent");
        conn.send(b"e\r\ndata: second\n\n\r\n0\r\n\r\n").unwrap();
    });
    let (_proxy, port) = h3_proxy(json!([{ "proxy": origin.url() }]));
    let mut h3 = H3::connect(port.addr).await;
    let request = http::Request::get(format!("https://{}/events", h3.authority))
        .body(())
        .unwrap();
    let mut stream = h3.send.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut first = stream.recv_data().await.unwrap().unwrap();
    assert_eq!(
        first.copy_to_bytes(first.remaining()),
        &b"data: first\n\n"[..]
    );
    got_first.send(()).unwrap();
    let mut rest = Vec::new();
    while let Some(mut data) = stream.recv_data().await.unwrap() {
        rest.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    assert_eq!(rest, b"data: second\n\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_connections_with_many_streams_each() {
    let origin = Origin::answering(|request| ok(request.line()));
    let (_proxy, port) = h3_proxy(json!([{ "proxy": origin.url() }]));
    let mut tasks = Vec::new();
    for c in 0..16 {
        let h3 = H3::connect(port.addr).await;
        for s in 0..16 {
            let mut h3 = h3.clone();
            tasks.push(tokio::spawn(async move {
                let path = format!("/{c}/{s}");
                let reply = h3.get(&path).await;
                assert_eq!(reply.status, 200);
                assert_eq!(
                    String::from_utf8_lossy(&reply.body),
                    format!("GET {path} HTTP/1.1")
                );
            }));
        }
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_under_load_loses_no_request() {
    let port = reserve();
    let addr = port.addr;
    let sites = move |generation: u32| {
        json!([tls_site(
            HOST,
            addr,
            true,
            json!([{ "respond": { "body": format!("gen {generation}") } }]),
        )])
    };
    let proxy = Arc::new(Proxy::start(sites(0)));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut clients = Vec::new();
    for _ in 0..8 {
        let mut h3 = H3::connect(port.addr).await;
        let stop = stop.clone();
        clients.push(tokio::spawn(async move {
            let (mut served, mut failed) = (0u64, Vec::new());
            while !stop.load(Ordering::SeqCst) {
                match h3.request("GET", "/", &[], None).await {
                    Ok(reply) if reply.status == 200 => served += 1,
                    Ok(reply) => failed.push(format!("status {}", reply.status)),
                    Err(e) => failed.push(e),
                }
            }
            (h3, served, failed)
        }));
    }
    for generation in 1..=5 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let proxy = proxy.clone();
        let status = tokio::task::spawn_blocking(move || {
            proxy.rewrite(sites(generation));
            proxy.reload()
        })
        .await
        .unwrap();
        assert!(status.contains("generation"), "{status}");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop.store(true, Ordering::SeqCst);
    let mut total = 0;
    for client in clients {
        let (mut h3, served, failed) = client.await.unwrap();
        assert!(failed.is_empty(), "failed requests: {failed:?}");
        assert!(served > 0);
        total += served;
        assert_eq!(
            h3.get("/").await.body,
            b"gen 5",
            "a connection opened before the reloads gets the newest plan"
        );
    }
    println!("{total} h3 requests across 5 reloads, none failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_sends_goaway_and_finishes_open_requests() {
    let (arrived, slow_arrived) = mpsc::channel::<()>();
    let arrived = Mutex::new(arrived);
    let origin = Origin::answering(move |_| {
        arrived.lock().unwrap().send(()).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        ok("slow")
    });
    let (proxy, port) = h3_proxy(json!([{ "proxy": origin.url() }]));
    let (mut h3, closed) = H3::connect_watched(port.addr).await;
    let mut in_flight = h3.clone();
    let slow = tokio::spawn(async move { in_flight.get("/slow").await });
    tokio::task::spawn_blocking(move || slow_arrived.recv_timeout(support::PATIENCE).unwrap())
        .await
        .unwrap();

    proxy.signal(libc::SIGTERM);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after = h3.request("GET", "/late", &[], None).await;
    assert!(
        after.is_err(),
        "a request opened after the GOAWAY is refused"
    );

    let slow = slow.await.unwrap();
    assert_eq!((slow.status, &slow.body[..]), (200, &b"slow"[..]));
    let closed = tokio::time::timeout(support::PATIENCE, closed)
        .await
        .expect("the proxy closes the connection once its last stream is done")
        .unwrap();
    assert!(closed.is_h3_no_error(), "closed with H3_NO_ERROR: {closed}");
}
