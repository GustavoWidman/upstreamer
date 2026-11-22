//! HTTP/2 through the real binary over TLS: an `h2` crate client on a rustls connection that
//! offers ALPN h2, against sites served on an HTTPS listener (self-signed certificates, since
//! the configured pairs do not exist).

mod support;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};
use support::{Client, Origin, PATIENCE, Proxy, Reserved, dechunk, ok, payload, sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The proxy with `sites` behind an HTTPS listener (and the cleartext one the harness always
/// has). `http3` is off so only TCP is served.
struct Tls {
    proxy: Proxy,
    addr: SocketAddr,
    _port: Reserved,
}

impl Tls {
    fn start(sites: Value) -> Tls {
        Tls::start_with(sites, json!({}))
    }

    fn start_with(sites: Value, top: Value) -> Tls {
        let port = Reserved::new();
        Tls {
            proxy: https_proxy(sites, top, port.addr),
            addr: port.addr,
            _port: port,
        }
    }

    fn h2(&self, rt: &tokio::runtime::Runtime) -> H2 {
        rt.block_on(H2::connect(self.addr, "test.example"))
    }
}

/// The proxy with `sites` behind an HTTPS listener on `addr`, which another proxy may share
/// (the listeners set SO_REUSEPORT).
fn https_proxy(mut sites: Value, mut top: Value, addr: SocketAddr) -> Proxy {
    for site in sites.as_array_mut().unwrap() {
        site["tls"] = json!({
            "cert": "/nonexistent/fullchain.pem",
            "key": "/nonexistent/key.pem",
            "redirectHttp": false,
            "http3": false,
        });
    }
    top["listen"] = json!({ "http": [], "https": [addr] });
    Proxy::start_with(sites, top)
}

fn site(routes: Value) -> Value {
    json!([{ "name": "test", "hosts": ["test.example"], "routes": routes }])
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// An h2 client connection; its connection task runs on the test's runtime.
struct H2 {
    send: h2::client::SendRequest<Bytes>,
    host: String,
    done: tokio::task::JoinHandle<Result<(), h2::Error>>,
}

impl H2 {
    async fn connect(addr: SocketAddr, host: &str) -> H2 {
        let io = TlsStream::connect(addr, host, &[b"h2"]);
        assert_eq!(io.tls.alpn_protocol(), Some(&b"h2"[..]), "ALPN chose h2");
        let (send, conn) = h2::client::handshake(io).await.expect("h2 handshake");
        let done = tokio::spawn(conn);
        H2 {
            send,
            host: host.to_owned(),
            done,
        }
    }

    fn request(&self, method: &str, path: &str) -> http::request::Builder {
        http::Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.host))
    }

    /// Sends `req` with `body` (none when empty) and reads the whole response.
    async fn fetch(&mut self, req: http::Request<()>, body: &[u8]) -> Fetched {
        let exchange = async {
            let (response, stream) = self.start(req, body).await;
            drop(stream);
            read_response(response.await.expect("a response")).await
        };
        tokio::time::timeout(PATIENCE, exchange)
            .await
            .expect("the exchange finishes in time")
    }

    /// Sends `req` and its `body`; the request's stream stays open for a reset.
    async fn start(
        &mut self,
        req: http::Request<()>,
        body: &[u8],
    ) -> (h2::client::ResponseFuture, h2::SendStream<Bytes>) {
        let send = std::future::poll_fn(|cx| self.send.poll_ready(cx));
        send.await.expect("a stream is available");
        let (response, mut stream) = self
            .send
            .send_request(req, body.is_empty())
            .expect("the request goes out");
        if !body.is_empty() {
            send_all(&mut stream, Bytes::copy_from_slice(body)).await;
        }
        (response, stream)
    }
}

/// Sends `data` and ends the stream, waiting for window capacity as the server grants it.
async fn send_all(stream: &mut h2::SendStream<Bytes>, mut data: Bytes) {
    stream.reserve_capacity(data.len());
    while !data.is_empty() {
        let granted = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .expect("the stream stays open")
            .expect("capacity");
        let piece = data.split_to(granted.min(data.len()));
        stream.send_data(piece, data.is_empty()).unwrap();
    }
}

struct Fetched {
    status: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
    /// DATA payload sizes in arrival order.
    frames: Vec<usize>,
}

impl Fetched {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }
}

async fn read_response(response: http::Response<h2::RecvStream>) -> Fetched {
    let (parts, mut recv) = response.into_parts();
    let mut body = Vec::new();
    let mut frames = Vec::new();
    while let Some(data) = recv.data().await {
        let data = data.expect("the body arrives");
        recv.flow_control().release_capacity(data.len()).unwrap();
        frames.push(data.len());
        body.extend_from_slice(&data);
    }
    Fetched {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
        frames,
    }
}

/// One HTTP/1.1 request over TLS with ALPN http/1.1, read to the close: (status, fields,
/// body without chunk syntax).
fn h1_over_tls(
    addr: SocketAddr,
    host: &str,
    request: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut io = TlsStream::connect_blocking(addr, host, &[b"http/1.1"]);
    io.write_all(request.as_bytes()).unwrap();
    io.flush().unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        match io.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("reading the h1 response: {e}"),
        }
    }
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head")
        + 4;
    let head = String::from_utf8(raw[..end].to_vec()).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let fields: Vec<(String, String)> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let rest = &raw[end..];
    let chunked = fields
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.contains("chunked"));
    let body = if request.starts_with("HEAD ") {
        Vec::new()
    } else if chunked {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    (status, fields, body)
}

#[test]
fn curl_speaks_h2_to_the_binary() {
    let www = tempfile::tempdir().unwrap();
    std::fs::write(www.path().join("index.html"), "hello over h2\n").unwrap();
    let tls = Tls::start(site(json!([{ "files": { "root": www.path() } }])));
    let url = format!("https://test.example:{}/", tls.addr.port());
    let resolve = format!("test.example:{}:127.0.0.1", tls.addr.port());
    let args = [
        "--insecure",
        "--http2",
        "--resolve",
        &resolve,
        "--include",
        &url,
    ];
    let Some(get) = support::curl(&args) else {
        return;
    };
    let out = String::from_utf8(get.stdout).unwrap();
    assert!(get.status.success(), "{out}");
    assert!(out.starts_with("HTTP/2 200"), "{out}");
    assert!(out.contains("content-length: 14\r\n"), "{out}");
    assert!(out.ends_with("\r\n\r\nhello over h2\n"), "{out}");

    let head = support::curl(&[
        "--insecure",
        "--http2",
        "--resolve",
        &resolve,
        "--head",
        &url,
    ])
    .unwrap();
    let out = String::from_utf8(head.stdout).unwrap();
    assert!(out.starts_with("HTTP/2 200"), "{out}");
    assert!(
        out.contains("content-length: 14\r\n"),
        "HEAD keeps the length: {out}"
    );
}

#[test]
fn head_sends_the_length_and_no_body() {
    let www = tempfile::tempdir().unwrap();
    std::fs::write(www.path().join("big.bin"), payload(1 << 20)).unwrap();
    let tls = Tls::start(site(json!([{ "files": { "root": www.path() } }])));
    let rt = runtime();
    let mut h2 = tls.h2(&rt);
    let req = h2.request("HEAD", "/big.bin").body(()).unwrap();
    let head = rt.block_on(h2.fetch(req, b""));
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-length"), Some("1048576"));
    assert!(head.header("date").is_some(), "a local response is dated");
    assert!(head.body.is_empty() && head.frames.is_empty());
}

/// An origin that answers `POST /sha` with the SHA-256 of the body it got, `GET /big` with
/// 1 MiB of payload, and anything else with its request line.
fn hashing_origin() -> Origin {
    Origin::answering(|request| {
        let body = if request.header("transfer-encoding").is_some() {
            dechunk(&request.body)
        } else {
            request.body.clone()
        };
        match request.line() {
            "POST /sha HTTP/1.1" => {
                let framing = match (
                    request.header("content-length"),
                    request.header("transfer-encoding"),
                ) {
                    (Some(n), None) => format!("length {n}"),
                    (None, Some(te)) => format!("te {te}"),
                    other => panic!("request framing {other:?}"),
                };
                ok(&format!("{} {framing}", sha256(&body)))
            }
            "GET /big HTTP/1.1" => {
                // A request that ended with its HEADERS has no body upstream either.
                let framed = ["content-length", "transfer-encoding"];
                if framed.iter().any(|name| request.header(name).is_some()) {
                    return ok("a GET with framing fields");
                }
                let mut out =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", 1 << 20).into_bytes();
                out.extend_from_slice(&payload(1 << 20));
                out
            }
            line => ok(line),
        }
    })
}

#[test]
fn one_mebibyte_bodies_cross_both_ways_under_flow_control() {
    let www = tempfile::tempdir().unwrap();
    let file = payload(1 << 20);
    std::fs::write(www.path().join("big.bin"), &file).unwrap();
    let origin = hashing_origin();
    let tls = Tls::start(site(json!([
        { "when": { "path": ["/sha", "/big"] }, "proxy": origin.url() },
        { "files": { "root": www.path() } },
    ])));
    let rt = runtime();
    let mut h2 = tls.h2(&rt);
    let want = sha256(&file);

    // The client's windows are 64 KiB: the server sends only what they grant.
    for path in ["/big.bin", "/big"] {
        let req = h2.request("GET", path).body(()).unwrap();
        let got = rt.block_on(h2.fetch(req, b""));
        assert_eq!(got.status, 200, "{path}");
        assert_eq!(got.header("content-length"), Some("1048576"), "{path}");
        assert_eq!(sha256(&got.body), want, "{path}");
        assert!(
            got.frames.len() >= 16,
            "{path}: {} frames",
            got.frames.len()
        );
    }

    // 1 MiB fits the 1 MiB stream window; 3 MiB gets through only if the proxy hands the
    // bytes it forwarded back to the client's window.
    let large = payload(3 << 20);
    for (i, body) in [&file, &file, &large, &large].into_iter().enumerate() {
        let declared = i % 2 == 0;
        let mut req = h2.request("POST", "/sha");
        if declared {
            req = req.header("content-length", body.len());
        }
        let got = rt.block_on(h2.fetch(req.body(()).unwrap(), body));
        assert_eq!(got.status, 200, "upload {i}");
        let framing = if declared {
            format!("length {}", body.len())
        } else {
            "te chunked".to_owned()
        };
        assert_eq!(
            String::from_utf8(got.body).unwrap(),
            format!("{} {framing}", sha256(body)),
            "upload {i}"
        );
    }
}

/// A gate the test opens for threads that wait on it.
#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);

impl Gate {
    fn open(&self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
    fn wait(&self) {
        let (open, cv) = &*self.0;
        let guard = cv
            .wait_timeout_while(open.lock().unwrap(), PATIENCE, |open| !*open)
            .unwrap();
        assert!(*guard.0, "the gate opened");
    }
}

#[test]
fn a_hundred_streams_run_at_once_on_one_connection() {
    const STREAMS: usize = 100;
    let arrived = Arc::new(AtomicUsize::new(0));
    let all_in = Gate::default();
    let origin = Origin::start({
        let (arrived, all_in) = (arrived.clone(), all_in.clone());
        move |stream, _| {
            let mut conn = Client::over(stream);
            while let Some(request) = conn.request() {
                if arrived.fetch_add(1, Ordering::SeqCst) + 1 == STREAMS {
                    all_in.open();
                }
                // Nothing is answered before every stream reached the origin.
                all_in.wait();
                let n: usize = request.line().split(' ').nth(1).unwrap()[1..]
                    .parse()
                    .unwrap();
                let body = payload(64 * 1024 + n);
                let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                    .into_bytes();
                out.extend_from_slice(&body);
                if conn.send(&out).is_err() {
                    return;
                }
            }
        }
    });
    let tls = Tls::start(site(json!([{ "proxy": origin.url() }])));
    let rt = runtime();
    let mut h2 = tls.h2(&rt);
    let fetched = rt.block_on(async {
        let mut pending = Vec::new();
        for n in 0..STREAMS {
            let req = h2.request("GET", &format!("/{n}")).body(()).unwrap();
            let (response, _) = h2.start(req, b"").await;
            pending.push(tokio::spawn(async move {
                read_response(response.await.expect("a response")).await
            }));
        }
        let mut fetched = Vec::new();
        for task in pending {
            fetched.push(task.await.unwrap());
        }
        fetched
    });
    assert_eq!(arrived.load(Ordering::SeqCst), STREAMS);
    for (n, got) in fetched.iter().enumerate() {
        assert_eq!(got.status, 200, "stream {n}");
        assert_eq!(
            sha256(&got.body),
            sha256(&payload(64 * 1024 + n)),
            "stream {n}"
        );
    }
    assert!(!h2.done.is_finished(), "the connection stays open");
}

/// Whether the peer closed `conn`: end of stream or a reset, not a read timeout.
fn peer_closed(conn: &Client) -> bool {
    let mut byte = [0u8; 1];
    match conn.stream().read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => e.kind() == io::ErrorKind::ConnectionReset,
    }
}

#[test]
fn rst_stream_cancels_the_upstream_request() {
    let (got, closed) = (Gate::default(), Gate::default());
    let origin = Origin::start({
        let (got, closed) = (got.clone(), closed.clone());
        move |stream, _| {
            let mut conn = Client::over(stream);
            if conn.head().is_none() {
                return;
            }
            got.open();
            if peer_closed(&conn) {
                closed.open();
            }
        }
    });
    let tls = Tls::start(site(json!([
        { "when": { "path": "/fast" }, "respond": { "body": "fast" } },
        { "proxy": origin.url() },
    ])));
    let rt = runtime();
    let mut h2 = tls.h2(&rt);
    rt.block_on(async {
        let req = h2.request("GET", "/slow").body(()).unwrap();
        let (_response, mut stream) = h2.start(req, b"").await;
        tokio::task::spawn_blocking(move || got.wait())
            .await
            .unwrap();
        stream.send_reset(h2::Reason::CANCEL);
        tokio::task::spawn_blocking(move || closed.wait())
            .await
            .unwrap();

        // The connection carries on.
        let req = h2.request("GET", "/fast").body(()).unwrap();
        let fast = h2.fetch(req, b"").await;
        assert_eq!((fast.status, &fast.body[..]), (200, &b"fast"[..]));
    });
}

#[test]
fn an_event_stream_flows_event_by_event_and_a_reset_closes_its_origin() {
    let next = Gate::default();
    let origin_closed = Gate::default();
    let origin = Origin::start({
        let (next, origin_closed) = (next.clone(), origin_closed.clone());
        move |stream, _| {
            let mut conn = Client::over(stream);
            let request = conn.request().unwrap();
            conn.send(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                  Cache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n\
                  b\r\ndata: one\n\n\r\n",
            )
            .unwrap();
            next.wait();
            conn.send(b"b\r\ndata: two\n\n\r\n").unwrap();
            if request.line().starts_with("GET /cut ") {
                // The client resets after the second event: the proxy closes this side.
                if peer_closed(&conn) {
                    origin_closed.open();
                }
                return;
            }
            conn.send(b"0\r\n\r\n").unwrap();
        }
    });
    let tls = Tls::start(site(json!([{ "proxy": origin.url() }])));
    let rt = runtime();
    let mut h2 = tls.h2(&rt);
    rt.block_on(async {
        for path in ["/live", "/cut"] {
            let req = h2
                .request("GET", path)
                .header("accept", "text/event-stream")
                .header("accept-encoding", "gzip, br, zstd")
                .body(())
                .unwrap();
            let (response, mut stream) = h2.start(req, b"").await;
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["content-type"], "text/event-stream");
            assert!(response.headers().get("content-encoding").is_none());
            let mut recv = response.into_body();
            let mut read = Vec::new();
            while !read.ends_with(b"data: one\n\n") {
                let data = recv.data().await.unwrap().unwrap();
                recv.flow_control().release_capacity(data.len()).unwrap();
                read.extend_from_slice(&data);
            }
            assert_eq!(
                read, b"data: one\n\n",
                "the first event arrives alone ({path})"
            );
            next.open();
            while !read.ends_with(b"data: two\n\n") {
                let data = recv.data().await.unwrap().unwrap();
                recv.flow_control().release_capacity(data.len()).unwrap();
                read.extend_from_slice(&data);
            }
            if path == "/cut" {
                stream.send_reset(h2::Reason::CANCEL);
                let closed = origin_closed.clone();
                tokio::task::spawn_blocking(move || closed.wait())
                    .await
                    .unwrap();
            } else {
                while let Some(data) = recv.data().await {
                    assert_eq!(data.unwrap(), "", "the stream ends with the origin's body");
                }
            }
            *next.0.0.lock().unwrap() = false;
        }
    });
}

#[test]
fn sigterm_sends_goaway_and_lets_open_streams_finish() {
    let release = Gate::default();
    let reached = Gate::default();
    let origin = Origin::start({
        let (release, reached) = (release.clone(), reached.clone());
        move |stream, _| {
            let mut conn = Client::over(stream);
            if conn.request().is_none() {
                return;
            }
            reached.open();
            release.wait();
            let _ = conn.send(&ok("finished"));
        }
    });
    let tls = Tls::start_with(
        site(json!([
            { "when": { "path": "/fast" }, "respond": { "body": "fast" } },
            { "proxy": origin.url() },
        ])),
        json!({ "timeouts": { "shutdown": "20s" } }),
    );
    let rt = runtime();
    let mut h2 = tls.h2(&rt);
    rt.block_on(async {
        let req = h2.request("GET", "/slow").body(()).unwrap();
        let (slow, _stream) = h2.start(req, b"").await;
        let wait = reached.clone();
        tokio::task::spawn_blocking(move || wait.wait())
            .await
            .unwrap();
        tls.proxy.signal(libc::SIGTERM);

        // New streams are refused once the GOAWAY arrives.
        let deadline = Instant::now() + PATIENCE;
        let refusal = loop {
            assert!(Instant::now() < deadline, "no GOAWAY arrived");
            let req = h2.request("GET", "/fast").body(()).unwrap();
            let sent = match std::future::poll_fn(|cx| h2.send.poll_ready(cx)).await {
                Ok(()) => h2
                    .send
                    .send_request(req, true)
                    .map(|(response, _)| response),
                Err(e) => Err(e),
            };
            match sent {
                Ok(response) => match response.await {
                    Ok(fast) => assert_eq!(fast.status(), 200),
                    Err(e) => break e,
                },
                Err(e) => break e,
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert!(
            refusal.is_go_away() || refusal.reason() == Some(h2::Reason::REFUSED_STREAM),
            "{refusal:?}"
        );

        release.open();
        let slow = read_response(slow.await.expect("the open stream finishes")).await;
        assert_eq!((slow.status, &slow.body[..]), (200, &b"finished"[..]));
    });
    let done = rt.block_on(async { tokio::time::timeout(PATIENCE, &mut h2.done).await });
    assert!(
        matches!(done, Ok(Ok(Ok(())))),
        "the connection closes cleanly: {done:?}"
    );
}

/// A Python interpreter that has httpx and h2: `UPSTREAMER_PYTHON`, or `python3`. Without
/// one the test that needs it skips, unless `UPSTREAMER_REQUIRE_PYTHON_H2` is set.
fn python_h2() -> Option<String> {
    let python = std::env::var("UPSTREAMER_PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let found = Command::new(&python)
        .args(["-c", "import httpx, h2"])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if found {
        return Some(python);
    }
    assert!(
        std::env::var_os("UPSTREAMER_REQUIRE_PYTHON_H2").is_none(),
        "{python} with httpx and h2 is required and not found"
    );
    eprintln!("skipped: {python} with httpx and h2 is not found (set UPSTREAMER_PYTHON)");
    None
}

/// Python's `h2` takes a connection as closed once it has read a GOAWAY, and httpx fails
/// a request whose stream the GOAWAY admits. Across a drain handed over to another process
/// on the same port, no request of such a client fails.
#[test]
fn a_python_h2_client_loses_no_request_across_a_drain() {
    let Some(python) = python_h2() else {
        return;
    };
    let release = Gate::default();
    let reached = Gate::default();
    let origin = Origin::start({
        let (release, reached) = (release.clone(), reached.clone());
        move |stream, _| {
            let mut conn = Client::over(stream);
            if conn.request().is_none() {
                return;
            }
            reached.open();
            release.wait();
            let _ = conn.send(&ok("slow"));
        }
    });
    let port = Reserved::new();
    let mut old = https_proxy(
        site(json!([
            { "when": { "path": "/slow" }, "proxy": origin.url() },
            { "respond": { "body": "old" } },
        ])),
        json!({ "timeouts": { "shutdown": "20s" } }),
        port.addr,
    );
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python/httpx_drain.py");
    let mut client = Command::new(&python)
        .arg(script)
        .arg(port.addr.port().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the client starts");
    let mut stdin = client.stdin.take().unwrap();
    let mut lines = io::BufReader::new(client.stdout.take().unwrap()).lines();
    let mut answer = || match lines.next() {
        Some(Ok(line)) => line,
        end => panic!("the client stopped answering: {end:?}"),
    };
    assert_eq!([answer(), answer()], ["old", "old"]);
    reached.wait();

    let _new = https_proxy(
        site(json!([{ "respond": { "body": "new" } }])),
        json!({}),
        port.addr,
    );
    old.signal(libc::SIGTERM);
    assert_eq!(old.notification(), "STOPPING=1");
    // The cores start to drain just after the notification.
    std::thread::sleep(Duration::from_millis(200));
    release.open();
    writeln!(stdin).unwrap();
    assert_eq!(
        answer(),
        "new",
        "the idle connection's request is retried on a new connection"
    );
    assert_eq!(answer(), "slow", "the request in progress finishes");
    assert_eq!(answer(), "new", "the next request goes to a new connection");
    let status = client.wait().unwrap();
    assert!(status.success(), "{status}");
    let status = old.exit_within(PATIENCE).expect("the old proxy exits");
    assert!(status.success(), "{status}");
}

#[test]
fn an_idle_connection_closes_and_an_open_stream_keeps_it() {
    let origin = Origin::start(|stream, _| {
        let mut conn = Client::over(stream);
        if conn.request().is_none() {
            return;
        }
        let _ = conn.send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(500));
            let _ = conn.send(b"2\r\nok\r\n");
        }
        let _ = conn.send(b"0\r\n\r\n");
    });
    let tls = Tls::start_with(
        site(json!([{ "proxy": origin.url() }])),
        json!({ "timeouts": { "keepAlive": "1s", "shutdown": "1s" } }),
    );
    let rt = runtime();
    let mut h2 = tls.h2(&rt);
    let req = h2.request("GET", "/slow").body(()).unwrap();
    let slow = rt.block_on(h2.fetch(req, b""));
    assert_eq!((slow.status, &slow.body[..]), (200, &b"okokokokok"[..]));
    let ended = Instant::now();
    let done = rt.block_on(async { tokio::time::timeout(PATIENCE, &mut h2.done).await });
    assert!(
        matches!(done, Ok(Ok(Ok(())))),
        "the connection closes cleanly: {done:?}"
    );
    let idle = ended.elapsed();
    assert!(
        idle >= Duration::from_millis(900),
        "closed {idle:?} after its last stream"
    );
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Replays the HTTPS cases of a routing table over HTTP/1.1 and over HTTP/2 against one
/// proxy, and returns the cases whose answers differ: status, body, and every response field
/// except Date and the HTTP/1.1 connection fields.
fn h1_and_h2_differences(table: &str) -> (usize, Vec<String>) {
    let routing = fixtures().join("routing");
    let table: Value =
        serde_json::from_str(&std::fs::read_to_string(routing.join(table)).unwrap()).unwrap();
    let out = routing.join(table["out"].as_str().unwrap());
    let api = Origin::answering(|request| ok(request.line()));
    let config = routing.join(table["config"].as_str().unwrap());
    let fragments = tempfile::tempdir().unwrap();
    let subst = |text: String| {
        text.replace("@out@", &out.display().to_string())
            .replace("@fixtures@", &fragments.path().display().to_string())
            .replace("http://127.0.0.1:7979", &api.url())
    };
    let siblings = config.parent().unwrap();
    let copies = fragments.path().join(siblings.file_name().unwrap());
    std::fs::create_dir(&copies).unwrap();
    for entry in std::fs::read_dir(siblings).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let text = subst(std::fs::read_to_string(&path).unwrap());
            std::fs::write(copies.join(path.file_name().unwrap()), text).unwrap();
        }
    }
    let mut doc: Value =
        serde_json::from_str(&subst(std::fs::read_to_string(&config).unwrap())).unwrap();
    let sites = doc["sites"].take();
    let names: Vec<String> = sites
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|site| site["hosts"].as_array().unwrap())
        .map(|host| host.as_str().unwrap().to_owned())
        .collect();
    let tls = Tls::start(sites);

    let rt = runtime();
    let mut connections: Vec<(String, H2)> = Vec::new();
    let mut sent = 0;
    let mut differences = Vec::new();
    for case in table["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let (method, url) = case["request"].as_str().unwrap().split_once(' ').unwrap();
        let Some(rest) = url.strip_prefix("https://") else {
            continue;
        };
        let (host, target) = rest.split_at(rest.find('/').unwrap());
        let headers: Vec<(String, String)> = case["headers"]
            .as_array()
            .map(|h| {
                h.iter()
                    .map(|pair| {
                        let pair = pair.as_array().unwrap();
                        (
                            pair[0].as_str().unwrap().to_owned(),
                            pair[1].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut request =
            format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        for (n, v) in &headers {
            request.push_str(&format!("{n}: {v}\r\n"));
        }
        if method == "POST" {
            request.push_str("Content-Length: 0\r\n");
        }
        request.push_str("\r\n");
        // A name without a certificate gets no handshake: such a case asks for its host
        // under a name the proxy has, which the pipeline answers 421 or routes by Host.
        let bare = host.split(':').next().unwrap().to_ascii_lowercase();
        let sni = if names.contains(&bare) {
            bare
        } else {
            names[0].clone()
        };
        let (h1_status, h1_fields, h1_body) = h1_over_tls(tls.addr, &sni, &request);

        if !connections.iter().any(|(h, _)| *h == sni) {
            connections.push((sni.clone(), rt.block_on(H2::connect(tls.addr, &sni))));
        }
        let h2 = &mut connections.iter_mut().find(|(h, _)| *h == sni).unwrap().1;
        let mut req = http::Request::builder()
            .method(method)
            .uri(format!("https://{host}{target}"));
        for (n, v) in &headers {
            req = req.header(n.as_str(), v.as_str());
        }
        let got = rt.block_on(h2.fetch(req.body(()).unwrap(), b""));
        sent += 1;

        let normalize = |fields: Vec<(String, String)>| {
            let mut fields: Vec<(String, String)> = fields
                .into_iter()
                .filter(|(n, _)| {
                    !matches!(
                        n.as_str(),
                        "date" | "connection" | "keep-alive" | "transfer-encoding"
                    )
                })
                .collect();
            fields.sort();
            fields
        };
        let h2_fields = got
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect();
        let (h1_fields, h2_fields) = (normalize(h1_fields), normalize(h2_fields));
        if h1_status != got.status || h1_body != got.body || h1_fields != h2_fields {
            differences.push(format!(
                "{name}: h1 {h1_status} {h1_fields:?} {} bytes, h2 {} {h2_fields:?} {} bytes",
                h1_body.len(),
                got.status,
                got.body.len()
            ));
        }
    }
    (sent, differences)
}

#[test]
fn heimdall_answers_the_same_over_h2_as_over_h1() {
    let (sent, differences) = h1_and_h2_differences("heimdall.json");
    assert!(sent >= 20, "{sent} cases");
    assert!(differences.is_empty(), "{differences:#?}");
}

#[test]
fn portfolio_answers_the_same_over_h2_as_over_h1() {
    let (sent, differences) = h1_and_h2_differences("portfolio.json");
    assert!(sent >= 90, "{sent} cases");
    assert!(differences.is_empty(), "{differences:#?}");
}

/// A rustls client connection over a TCP socket: blocking for HTTP/1.1, and through tokio's
/// traits for the `h2` client. Certificates are not verified (the proxy's are self-signed).
struct TlsStream<S> {
    sock: S,
    tls: rustls::ClientConnection,
}

fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

impl TlsStream<TcpStream> {
    fn connect_blocking(addr: SocketAddr, host: &str, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        let name = ServerName::try_from(host.to_owned()).unwrap();
        let mut tls = rustls::ClientConnection::new(client_config(alpn), name).unwrap();
        let mut sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(PATIENCE)).unwrap();
        while tls.is_handshaking() {
            tls.complete_io(&mut sock).unwrap();
        }
        TlsStream { sock, tls }
    }
}

impl Read for TlsStream<TcpStream> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.tls, &mut self.sock).read(buf)
    }
}

impl Write for TlsStream<TcpStream> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.tls, &mut self.sock).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        rustls::Stream::new(&mut self.tls, &mut self.sock).flush()
    }
}

impl TlsStream<tokio::net::TcpStream> {
    /// Handshakes blocking, then hands the socket to tokio.
    fn connect(addr: SocketAddr, host: &str, alpn: &[&[u8]]) -> TlsStream<tokio::net::TcpStream> {
        let TlsStream { sock, tls } = TlsStream::connect_blocking(addr, host, alpn);
        sock.set_nonblocking(true).unwrap();
        TlsStream {
            sock: tokio::net::TcpStream::from_std(sock).unwrap(),
            tls,
        }
    }

    /// Writes out every record rustls has ready.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tls.wants_write() {
            let mut io = Polled {
                sock: &mut self.sock,
                cx,
            };
            match self.tls.write_tls(&mut io) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// A tokio socket as `Read + Write` for rustls, inside a poll: not ready is `WouldBlock`.
struct Polled<'a, 'b> {
    sock: &'a mut tokio::net::TcpStream,
    cx: &'a mut Context<'b>,
}

impl Read for Polled<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut *self.sock).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl Write for Polled<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.sock).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for TlsStream<tokio::net::TcpStream> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.tls.reader().read(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Poll::Ready(Ok(())),
                Err(e) => return Poll::Ready(Err(e)),
            }
            if let Poll::Ready(Err(e)) = this.poll_send(cx) {
                return Poll::Ready(Err(e));
            }
            let mut io = Polled {
                sock: &mut this.sock,
                cx,
            };
            match this.tls.read_tls(&mut io) {
                Ok(0) => return Poll::Ready(Ok(())),
                Ok(_) => {
                    this.tls.process_new_packets().map_err(io::Error::other)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for TlsStream<tokio::net::TcpStream> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let n = this.tls.writer().write(buf)?;
            if n > 0 {
                if let Poll::Ready(Err(e)) = this.poll_send(cx) {
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(n));
            }
            ready!(this.poll_send(cx))?;
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_send(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tls.send_close_notify();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.sock).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
