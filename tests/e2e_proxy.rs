//! The reverse proxy through the real binary: one upstreamer process per test, origins that
//! are threads in the test, and clients that read the bytes on the wire.

mod support;

use serde_json::json;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use support::{
    Client, Origin, PATIENCE, Proxy, closed_addr, eventually, ok, payload, sha256, site,
};

/// A proxy with one site that forwards everything to `origin`.
fn proxy_to(origin: &Origin) -> Proxy {
    Proxy::start(site(json!([{ "proxy": origin.url() }])))
}

#[test]
fn a_thousand_requests_reuse_one_upstream_connection() {
    let origin = Origin::answering(|_| ok("pooled"));
    let proxy = Proxy::start_with(
        site(json!([{ "proxy": origin.url() }])),
        json!({ "workers": 1 }),
    );
    let mut client = proxy.client();
    for _ in 0..1000 {
        let response = client.get("/");
        assert_eq!((response.status, response.text().as_str()), (200, "pooled"));
    }
    assert_eq!(origin.connections(), 1, "one upstream connection");
}

#[test]
fn the_origin_gets_the_clients_request_with_forwarding_fields() {
    let origin = Origin::answering(|request| ok(&request.head));
    let proxy = Proxy::start(site(json!([{
        "proxy": {
            "to": origin.url(),
            "headers": { "X-Real-IP": "{remote_host}", "X-Dropped": null },
        }
    }])));
    let mut client = proxy.client();
    let response = client.roundtrip(
        "GET /a%20b/./c?sig=%2F%2f&x HTTP/1.1\r\n\
         Host: Example.Test:8080\r\n\
         X-Forwarded-For: 203.0.113.9\r\n\
         X-Dropped: 1\r\n\
         X-Kept: yes\r\n\
         Connection: keep-alive, X-Hop\r\n\
         X-Hop: secret\r\n\
         Keep-Alive: timeout=5\r\n\
         \r\n",
    );
    let seen = response.text();
    assert_eq!(
        seen.lines().next(),
        Some("GET /a%20b/./c?sig=%2F%2f&x HTTP/1.1"),
        "the request-target goes upstream byte for byte"
    );
    let field = |name| support::header(&seen, name);
    assert_eq!(
        field("host"),
        Some("Example.Test:8080"),
        "Host passes through"
    );
    assert_eq!(field("x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(field("x-forwarded-proto"), Some("http"));
    assert_eq!(field("x-forwarded-host"), Some("example.test"));
    assert_eq!(field("x-real-ip"), Some("127.0.0.1"));
    assert_eq!(field("x-kept"), Some("yes"));
    for gone in ["x-dropped", "x-hop", "keep-alive", "connection"] {
        assert_eq!(
            field(gone),
            None,
            "{gone} must not reach the origin:\n{seen}"
        );
    }
}

#[test]
fn a_stripped_prefix_is_cut_from_the_forwarded_target() {
    let origin = Origin::answering(|request| ok(request.line()));
    let proxy = Proxy::start(site(json!([
        { "when": { "path": "/daemon/*" },
          "routes": [{ "stripPrefix": "/daemon" }, { "proxy": origin.url() }] },
        { "respond": { "status": 404, "body": "no route" } },
    ])));
    let mut client = proxy.client();
    assert_eq!(
        client.get("/daemon/socket.io/?EIO=4&t=%2B").text(),
        "GET /socket.io/?EIO=4&t=%2B HTTP/1.1"
    );
    assert_eq!(client.get("/other").status, 404);
}

#[test]
fn a_chunked_response_passes_through_byte_identical() {
    const BODY: &[u8] =
        b"5;ext=1\r\nhello\r\n3\r\nabc\r\n10\r\n0123456789abcdef\r\n0\r\nX-Trailer: t\r\n\r\n";
    let origin = Origin::answering(|_| {
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(BODY);
        response
    });
    let proxy = Proxy::start_with(
        site(json!([{ "proxy": origin.url() }])),
        json!({ "workers": 1 }),
    );
    let mut client = proxy.client();
    for _ in 0..3 {
        client
            .send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        let head = client.head().unwrap();
        assert_eq!(support::header(&head, "transfer-encoding"), Some("chunked"));
        assert_eq!(support::header(&head, "content-length"), None);
        assert_eq!(
            String::from_utf8_lossy(&client.chunked_raw()),
            String::from_utf8_lossy(BODY),
            "chunk sizes, extensions and trailers as the origin sent them"
        );
    }
    assert_eq!(
        origin.connections(),
        1,
        "the connection is reused after a chunked body"
    );
}

#[test]
fn a_chunked_request_passes_through_byte_identical() {
    const BODY: &[u8] = b"4;a=b\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n";
    let origin = Origin::answering(|request| {
        if request.line().starts_with("POST ") {
            assert_eq!(request.header("transfer-encoding"), Some("chunked"));
            assert_eq!(request.header("content-length"), None);
        }
        ok(&String::from_utf8_lossy(&request.body))
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    client
        .send(b"POST /up HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n")
        .unwrap();
    // In pieces, so the proxy forwards the body across several reads.
    for piece in BODY.chunks(7) {
        client.send(piece).unwrap();
        std::thread::sleep(Duration::from_millis(5));
    }
    let response = client.response(false).unwrap();
    assert_eq!(response.body, BODY);
    assert_eq!(
        client.get("/").status,
        200,
        "the client connection is reused"
    );
}

/// An origin that sends an event stream: the head at once, then one event each time the
/// test asks for it.
fn event_origin(framing: &'static str) -> (Origin, mpsc::Sender<&'static str>) {
    let (next, events) = mpsc::channel::<&'static str>();
    let events = Mutex::new(events);
    let origin = Origin::start(move |stream, _| {
        let mut conn = Client::over(stream);
        conn.request().unwrap();
        conn.send(
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{framing}\r\n")
                .as_bytes(),
        )
        .unwrap();
        while let Ok(event) = events.lock().unwrap().recv() {
            let chunk = if framing.is_empty() {
                event.to_owned()
            } else {
                format!("{:x}\r\n{event}\r\n", event.len())
            };
            conn.send(chunk.as_bytes()).unwrap();
        }
    });
    (origin, next)
}

/// Reads one chunk of a chunked body.
fn read_chunk(client: &mut Client) -> String {
    let size = client.head_line();
    let size = usize::from_str_radix(size.trim(), 16).unwrap();
    let data = client.bytes(size + 2);
    String::from_utf8_lossy(&data[..size]).into_owned()
}

#[test]
fn server_sent_events_arrive_one_by_one() {
    // A chunked stream passes through; a close-delimited one is chunked by the proxy.
    for framing in ["Transfer-Encoding: chunked\r\n", ""] {
        let (origin, next) = event_origin(framing);
        let proxy = proxy_to(&origin);
        let mut client = proxy.client();
        client
            .send(b"GET /api/live HTTP/1.1\r\nHost: test\r\nAccept: text/event-stream\r\n\r\n")
            .unwrap();
        let head = client.head().unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert_eq!(
            support::header(&head, "content-type"),
            Some("text/event-stream")
        );
        assert_eq!(support::header(&head, "transfer-encoding"), Some("chunked"));
        for event in ["data: one\n\n", "data: two\n\n", "data: three\n\n"] {
            // The origin holds the next event until this one was read here.
            next.send(event).unwrap();
            assert_eq!(read_chunk(&mut client), event);
        }
    }
}

#[test]
fn a_websocket_echoes_through_the_proxy() {
    let origin = Origin::start(|stream, _| {
        let mut conn = Client::over(stream);
        let request = conn.request().unwrap();
        assert_eq!(request.line(), "GET /ws?room=1 HTTP/1.1");
        assert!(
            request
                .header("upgrade")
                .unwrap()
                .eq_ignore_ascii_case("websocket")
        );
        assert!(
            request
                .header("connection")
                .unwrap()
                .eq_ignore_ascii_case("upgrade")
        );
        assert_eq!(request.header("sec-websocket-version"), Some("13"));
        let accept = support::websocket_accept(request.header("sec-websocket-key").unwrap());
        conn.send(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        loop {
            let (opcode, payload) = support::read_websocket_frame(&mut conn);
            conn.send(&support::websocket_frame(opcode, &payload, None))
                .unwrap();
            if opcode == 8 {
                return;
            }
        }
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    client
        .send(
            format!(
                "GET /ws?room=1 HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let head = client.head().unwrap();
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{head}"
    );
    assert!(
        support::header(&head, "upgrade")
            .unwrap()
            .eq_ignore_ascii_case("websocket")
    );
    assert!(
        support::header(&head, "connection")
            .unwrap()
            .eq_ignore_ascii_case("upgrade")
    );
    assert_eq!(
        support::header(&head, "sec-websocket-accept"),
        Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "the accept value of RFC 6455's sample key"
    );
    for text in ["hello", "second message"] {
        client
            .send(&support::websocket_frame(
                1,
                text.as_bytes(),
                Some([7, 11, 13, 17]),
            ))
            .unwrap();
        assert_eq!(
            support::read_websocket_frame(&mut client),
            (1, text.as_bytes().to_vec())
        );
    }
    client
        .send(&support::websocket_frame(8, b"", Some([1, 2, 3, 4])))
        .unwrap();
    assert_eq!(support::read_websocket_frame(&mut client), (8, Vec::new()));
    assert!(client.closed(), "the tunnel ends when the origin closes");
}

#[test]
fn an_upgrade_to_another_protocol_tunnels_bytes_both_ways() {
    const GREETING: &[u8] = b"\x01server-key-frame";
    let blob = Arc::new(payload(256 * 1024));
    let (closed_tx, closed) = mpsc::channel();
    let closed_tx = Mutex::new(closed_tx);
    let origin = Origin::start({
        let blob = blob.clone();
        move |stream, _| {
            let mut conn = Client::over(stream);
            let request = conn.request().unwrap();
            assert_eq!(request.header("upgrade"), Some("DERP"));
            // The first frame follows the 101 in the same write.
            let mut hello =
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
                    .to_vec();
            hello.extend_from_slice(GREETING);
            conn.send(&hello).unwrap();
            let got = conn.bytes(blob.len());
            conn.send(sha256(&got).as_bytes()).unwrap();
            conn.send(&blob).unwrap();
            let end = conn.closed();
            closed_tx.lock().unwrap().send(end).unwrap();
        }
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    client
        .send(b"GET /derp HTTP/1.1\r\nHost: test\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n")
        .unwrap();
    let head = client.head().unwrap();
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert_eq!(support::header(&head, "upgrade"), Some("DERP"));
    assert_eq!(client.bytes(GREETING.len()), GREETING);
    client.send(&blob).unwrap();
    assert_eq!(
        String::from_utf8(client.bytes(64)).unwrap(),
        sha256(&blob),
        "256 KiB client to origin"
    );
    assert_eq!(sha256(&client.bytes(blob.len())), sha256(&blob), "and back");
    drop(client);
    assert!(
        closed.recv_timeout(PATIENCE).unwrap(),
        "the origin's side closes when the client goes"
    );
}

/// An origin for transfers: `POST` answers the SHA-256 of the body it read, `GET` answers
/// `blob`.
fn transfer_origin(blob: Arc<Vec<u8>>) -> Origin {
    Origin::answering(move |request| {
        if request.line().starts_with("GET ") {
            let mut response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", blob.len()).into_bytes();
            response.extend_from_slice(&blob);
            return response;
        }
        let data = match request.header("transfer-encoding") {
            Some(_) => support::dechunk(&request.body),
            None => request.body.clone(),
        };
        ok(&sha256(&data))
    })
}

#[test]
fn a_megabyte_goes_up_and_down_intact() {
    let blob = Arc::new(payload(1 << 20));
    let origin = transfer_origin(blob.clone());
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();

    let mut upload = format!(
        "POST /up HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n",
        blob.len()
    )
    .into_bytes();
    upload.extend_from_slice(&blob);
    client.send(&upload).unwrap();
    assert_eq!(
        client.response(false).unwrap().text(),
        sha256(&blob),
        "1 MiB up"
    );

    let download = client.get("/down");
    assert_eq!(download.body.len(), blob.len());
    assert_eq!(sha256(&download.body), sha256(&blob), "1 MiB down");
}

#[test]
fn curl_moves_a_megabyte_up_and_down() {
    let blob = Arc::new(payload(1 << 20));
    let origin = transfer_origin(blob.clone());
    let proxy = proxy_to(&origin);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blob");
    std::fs::write(&file, &*blob).unwrap();
    let data = format!("@{}", file.display());

    // curl sends `Expect: 100-continue` before a body this large and waits for the answer.
    let Some(up) = support::curl(&["--data-binary", &data, &proxy.url("/up")]) else {
        return;
    };
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&up.stdout), sha256(&blob));

    let chunked = support::curl(&[
        "--data-binary",
        &data,
        "-H",
        "Transfer-Encoding: chunked",
        &proxy.url("/up"),
    ])
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&chunked.stdout),
        sha256(&blob),
        "chunked upload"
    );

    let down = support::curl(&[&proxy.url("/down")]).unwrap();
    assert_eq!(sha256(&down.stdout), sha256(&blob));
}

#[test]
fn a_slow_request_head_is_cut_at_the_header_timeout() {
    let proxy = Proxy::start_with(
        site(json!([{ "respond": { "body": "ok" } }])),
        json!({ "timeouts": { "header": "300ms", "shutdown": "1s" } }),
    );
    let mut client = proxy.client();
    let started = Instant::now();
    client.send(b"GET / HTTP/1.1\r\nHost: test\r\n").unwrap();
    // One more byte now and then would keep a per-read timeout alive forever.
    let stream = client.stream().try_clone().unwrap();
    std::thread::spawn(move || {
        let mut stream = stream;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(100));
            if stream.write_all(b"X-Slow: 1\r\n").is_err() {
                return;
            }
        }
    });
    let response = client.response(false).expect("an answer before the close");
    let waited = started.elapsed();
    assert_eq!(response.status, 408);
    assert_eq!(response.header("connection"), Some("close"));
    assert!(
        waited >= Duration::from_millis(280) && waited < Duration::from_secs(3),
        "cut after the 300 ms header timeout, whatever the client keeps sending: {waited:?}"
    );
    assert!(client.closed());
}

#[test]
fn an_idle_connection_is_closed_at_the_keep_alive_timeout() {
    let proxy = Proxy::start_with(
        site(json!([{ "respond": { "body": "ok" } }])),
        json!({ "timeouts": { "keepAlive": "600ms", "shutdown": "1s" } }),
    );
    let mut client = proxy.client();
    let started = Instant::now();
    let mut idle_since = started;
    // Requests a quarter of the timeout apart, so a stalled test thread does not outlast it.
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(client.get("/").status, 200);
        idle_since = Instant::now();
    }
    assert!(
        started.elapsed() >= Duration::from_millis(1200),
        "requests 150 ms apart kept the connection past two timeouts"
    );
    assert!(client.closed(), "closed without a response");
    let waited = idle_since.elapsed();
    assert!(
        waited >= Duration::from_millis(580) && waited < Duration::from_secs(3),
        "closed 600 ms after the last request: {waited:?}"
    );
}

#[test]
fn a_client_that_leaves_mid_upload_closes_the_upstream_connection() {
    let (seen_tx, seen) = mpsc::channel();
    let seen_tx = Mutex::new(seen_tx);
    let origin = Origin::start(move |mut stream, _| {
        let mut received = 0;
        let mut chunk = [0u8; 16 * 1024];
        let end = loop {
            match stream.read(&mut chunk) {
                Ok(0) => break "closed",
                Ok(n) => received += n,
                Err(_) => break "reset",
            }
        };
        seen_tx.lock().unwrap().send((end, received)).unwrap();
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    client
        .send(b"POST /up HTTP/1.1\r\nHost: test\r\nContent-Length: 1048576\r\n\r\n")
        .unwrap();
    client.send(&payload(10_000)).unwrap();
    eventually("the origin gets the request", || origin.connections() == 1);
    std::thread::sleep(Duration::from_millis(100));
    drop(client);
    let (_, received) = seen
        .recv_timeout(PATIENCE)
        .expect("the origin's connection ends");
    assert!(
        (10_000..1_048_576).contains(&received),
        "the origin got the head and the bytes sent, then the close: {received}"
    );
}

#[test]
fn a_client_that_leaves_mid_download_closes_the_upstream_connection() {
    let (closed_tx, closed) = mpsc::channel();
    let closed_tx = Mutex::new(closed_tx);
    let origin = Origin::start(move |stream, _| {
        let mut conn = Client::over(stream);
        conn.request().unwrap();
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
            .unwrap();
        // Nothing more is sent: only the close of this connection ends the read.
        closed_tx.lock().unwrap().send(conn.closed()).unwrap();
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    client
        .send(b"GET /live HTTP/1.1\r\nHost: test\r\n\r\n")
        .unwrap();
    client.head().unwrap();
    assert_eq!(read_chunk(&mut client), "first");
    drop(client);
    assert!(
        closed
            .recv_timeout(PATIENCE)
            .expect("the origin's connection ends"),
        "closed while the origin was silent"
    );
}

#[test]
fn a_client_that_leaves_while_the_origin_is_silent_closes_the_upstream_connection() {
    let (closed_tx, closed) = mpsc::channel();
    let closed_tx = Mutex::new(closed_tx);
    let origin = Origin::start(move |stream, _| {
        let mut conn = Client::over(stream);
        conn.request().unwrap();
        // No answer, ever: only the close of this connection ends the read.
        closed_tx.lock().unwrap().send(conn.closed()).unwrap();
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    client
        .send(b"GET /slow HTTP/1.1\r\nHost: test\r\n\r\n")
        .unwrap();
    eventually("the origin gets the request", || origin.connections() == 1);
    drop(client);
    let left = Instant::now();
    assert!(
        closed
            .recv_timeout(PATIENCE)
            .expect("the origin's connection ends")
    );
    assert!(
        left.elapsed() < Duration::from_secs(5),
        "noticed about a second into the origin's silence: {:?}",
        left.elapsed()
    );
}

#[test]
fn an_idle_upstream_connection_is_closed_after_its_idle_timeout() {
    let (closed_tx, closed) = mpsc::channel();
    let closed_tx = Mutex::new(closed_tx);
    let origin = Origin::start(move |stream, _| {
        let mut conn = Client::over(stream);
        while let Some(request) = conn.request() {
            conn.send(&ok(request.line())).unwrap();
        }
        closed_tx.lock().unwrap().send(Instant::now()).unwrap();
    });
    let proxy = Proxy::start(site(json!([{
        "proxy": { "to": origin.url(), "timeouts": { "idle": "1s" } }
    }])));
    let mut client = proxy.client();
    assert_eq!(client.get("/").status, 200);
    let idle_since = Instant::now();
    let closed_at = closed
        .recv_timeout(PATIENCE)
        .expect("the pooled connection is closed");
    let idle = closed_at.duration_since(idle_since);
    assert!(
        idle >= Duration::from_secs(1) && idle < Duration::from_secs(12),
        "kept for the 1 s idle timeout, closed by a sweep soon after: {idle:?}"
    );
    assert_eq!(
        client.get("/again").status,
        200,
        "the next request dials again"
    );
    assert_eq!(origin.connections(), 2);
}

#[test]
fn a_reload_keeps_the_pooled_connections_of_origins_that_stay() {
    let (closed_tx, closed) = mpsc::channel();
    let closed_tx = Mutex::new(closed_tx);
    let serve = |name: &'static str, closed: Option<Mutex<mpsc::Sender<()>>>| {
        Origin::start(move |stream, _| {
            let mut conn = Client::over(stream);
            while conn.request().is_some() {
                conn.send(&ok(name)).unwrap();
            }
            if let Some(closed) = &closed {
                closed.lock().unwrap().send(()).unwrap();
            }
        })
    };
    let (stays, goes) = (serve("stays", None), serve("goes", Some(closed_tx)));
    let sites = |other: Option<&Origin>| {
        let mut routes = vec![json!({ "when": { "path": "/stays" }, "proxy": stays.url() })];
        if let Some(other) = other {
            // Listed first, so the origin that stays changes its place in the plan.
            routes.insert(
                0,
                json!({ "when": { "path": "/goes" }, "proxy": other.url() }),
            );
        }
        routes.push(json!({ "respond": { "status": 404, "body": "no route" } }));
        site(json!(routes))
    };
    let proxy = Proxy::start_with(sites(Some(&goes)), json!({ "workers": 1 }));
    let mut client = proxy.client();
    assert_eq!(client.get("/stays").text(), "stays");
    assert_eq!(client.get("/goes").text(), "goes");

    proxy.rewrite(sites(None));
    proxy.reload();
    closed
        .recv_timeout(PATIENCE)
        .expect("the connection to the origin that left the config is closed");
    assert_eq!(client.get("/goes").status, 404);
    assert_eq!(client.get("/stays").text(), "stays");
    assert_eq!(
        stays.connections(),
        1,
        "the connection to the origin that stayed served the request after the reload"
    );
}

/// An origin whose first connection answers one request, then reads the next one and closes
/// without answering: what a pooled connection looks like when the origin gave up on it just
/// as the request was sent. Later connections answer everything.
fn origin_with_a_stale_first_connection() -> (Origin, Arc<AtomicUsize>) {
    let unanswered = Arc::new(AtomicUsize::new(0));
    let origin = Origin::start({
        let unanswered = unanswered.clone();
        move |stream, index| {
            let mut conn = Client::over(stream);
            let mut served = 0;
            while let Some(request) = conn.request() {
                if index == 0 && served == 1 {
                    unanswered.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                served += 1;
                conn.send(&ok(&format!("{} on connection {index}", request.line())))
                    .unwrap();
            }
        }
    });
    (origin, unanswered)
}

#[test]
fn a_request_that_dies_on_a_reused_connection_is_retried_for_get() {
    let (origin, unanswered) = origin_with_a_stale_first_connection();
    let proxy = Proxy::start_with(
        site(json!([{ "proxy": origin.url() }])),
        json!({ "workers": 1 }),
    );
    let mut client = proxy.client();
    assert_eq!(client.get("/1").text(), "GET /1 HTTP/1.1 on connection 0");
    let retried = client.get("/2");
    assert_eq!(
        (retried.status, retried.text().as_str()),
        (200, "GET /2 HTTP/1.1 on connection 1"),
        "sent again on a new connection"
    );
    assert_eq!(
        unanswered.load(Ordering::SeqCst),
        1,
        "the first try reached the origin"
    );
    assert_eq!(origin.connections(), 2);
}

#[test]
fn a_request_that_dies_on_a_reused_connection_is_not_retried_for_post() {
    let (origin, unanswered) = origin_with_a_stale_first_connection();
    let proxy = Proxy::start_with(
        site(json!([{ "proxy": origin.url() }])),
        json!({ "workers": 1 }),
    );
    let mut client = proxy.client();
    assert_eq!(client.get("/1").status, 200);
    let post =
        client.roundtrip("POST /pay HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\ncash");
    assert_eq!(
        post.status, 502,
        "a POST the origin may have acted on is not sent twice"
    );
    assert_eq!(unanswered.load(Ordering::SeqCst), 1);
    assert_eq!(origin.connections(), 1, "no second connection was tried");
    assert_eq!(
        client.get("/3").text(),
        "GET /3 HTTP/1.1 on connection 1",
        "the client's connection survives the 502"
    );
}

#[test]
fn a_connection_the_origin_closed_while_idle_is_not_used() {
    // No `Connection: close`: the origin just closes after each response.
    let origin = Origin::start(|stream, index| {
        let mut conn = Client::over(stream);
        if conn.request().is_some() {
            conn.send(&ok(&format!("connection {index}"))).unwrap();
        }
    });
    let proxy = Proxy::start_with(
        site(json!([{ "proxy": origin.url() }])),
        json!({ "workers": 1 }),
    );
    let mut client = proxy.client();
    for i in 0..5 {
        let post =
            client.roundtrip("POST /pay HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\ncash");
        assert_eq!(
            (post.status, post.text()),
            (200, format!("connection {i}")),
            "a POST never meets the closed connection"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn upstream_failures_go_through_the_error_routes() {
    let silent = Origin::start(|stream, _| {
        let mut conn = Client::over(stream);
        conn.request();
        conn.closed();
    });
    let refused = closed_addr();
    let proxy = Proxy::start(json!([{
        "name": "test",
        "hosts": ["*"],
        "routes": [
            { "when": { "path": "/refused" }, "proxy": format!("http://{refused}") },
            { "when": { "path": "/silent" },
              "proxy": { "to": silent.url(), "timeouts": { "responseHeader": "300ms" } } },
            { "when": { "path": "/unhandled" }, "error": 503 },
        ],
        "errors": [
            { "status": [502], "routes": [
                { "headers": { "X-Error": "{err.status_code}" } },
                { "respond": { "body": "no upstream ({err.status_code} {err.status_text})" } },
            ] },
            { "status": [504], "routes": [{ "respond": { "body": "too slow", "status": 504 } }] },
        ],
    }]));
    let mut client = proxy.client();

    let refused = client.get("/refused");
    assert_eq!(refused.status, 502);
    assert_eq!(refused.text(), "no upstream (502 Bad Gateway)");
    assert_eq!(refused.header("x-error"), Some("502"));
    assert_eq!(
        refused.header("content-type"),
        Some("text/plain; charset=utf-8")
    );

    let started = Instant::now();
    let silent = client.get("/silent");
    let waited = started.elapsed();
    assert_eq!((silent.status, silent.text().as_str()), (504, "too slow"));
    assert!(
        waited >= Duration::from_millis(280) && waited < Duration::from_secs(3),
        "after the 300 ms response-header timeout: {waited:?}"
    );

    let unhandled = client.get("/unhandled");
    assert_eq!(
        (unhandled.status, unhandled.body.len()),
        (503, 0),
        "no route for 503: bare"
    );
    assert_eq!(client.get("/nothing").status, 404, "all on one connection");
}

#[test]
fn a_head_request_gets_the_head_only() {
    let origin = Origin::answering(|request| {
        assert_eq!(request.line(), "HEAD /file HTTP/1.1");
        b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\nETag: \"v1\"\r\n\r\n".to_vec()
    });
    let proxy = Proxy::start(site(json!([
        { "when": { "path": "/local" }, "respond": { "body": "seven b" } },
        { "proxy": origin.url() },
    ])));
    let mut client = proxy.client();
    let proxied = client.roundtrip("HEAD /file HTTP/1.1\r\nHost: test\r\n\r\n");
    assert_eq!(proxied.status, 200);
    assert_eq!(
        proxied.header("content-length"),
        Some("12345"),
        "the origin's length"
    );
    assert_eq!(proxied.header("etag"), Some("\"v1\""));

    let local = client.roundtrip("HEAD /local HTTP/1.1\r\nHost: test\r\n\r\n");
    assert_eq!(
        local.header("content-length"),
        Some("7"),
        "the length GET would send"
    );
    let get = client.get("/local");
    assert_eq!(
        get.text(),
        "seven b",
        "no body bytes were left on the connection"
    );
}

#[test]
fn expect_100_continue_is_answered_before_the_body_is_read() {
    let origin = Origin::answering(|request| {
        assert_eq!(request.header("expect"), None, "Expect is not forwarded");
        ok(&String::from_utf8_lossy(&request.body))
    });
    let proxy = Proxy::start(site(json!([
        { "when": { "path": "/local" }, "respond": { "status": 403, "body": "no" } },
        { "proxy": origin.url() },
    ])));
    let mut client = proxy.client();
    client
        .send(
            b"POST /up HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n",
        )
        .unwrap();
    assert_eq!(client.head().unwrap(), "HTTP/1.1 100 Continue\r\n\r\n");
    client.send(b"hello").unwrap();
    let response = client.response(false).unwrap();
    assert_eq!((response.status, response.text().as_str()), (200, "hello"));

    // A route that never reads the body answers at once; the body the client held back
    // cannot be skipped, so the connection closes.
    client
        .send(b"POST /local HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
        .unwrap();
    let refused = client.response(false).unwrap();
    assert_eq!(refused.status, 403);
    assert_eq!(refused.header("connection"), Some("close"));
    assert!(client.closed());
}

#[test]
fn pipelined_requests_are_answered_in_order() {
    let origin = Origin::answering(|request| ok(request.line()));
    let proxy = Proxy::start(site(json!([
        { "when": { "path": "/local" }, "respond": { "body": "local" } },
        { "proxy": origin.url() },
    ])));
    let mut client = proxy.client();
    let mut burst = String::new();
    for path in ["/a", "/local", "/b", "/c"] {
        burst.push_str(&format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n"));
    }
    // The last request arrives split across two packets.
    let (first, last) = burst.split_at(burst.len() - 9);
    client.send(first.as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    client.send(last.as_bytes()).unwrap();
    let bodies: Vec<String> = (0..4)
        .map(|_| client.response(false).unwrap().text())
        .collect();
    assert_eq!(
        bodies,
        [
            "GET /a HTTP/1.1",
            "local",
            "GET /b HTTP/1.1",
            "GET /c HTTP/1.1"
        ]
    );
}

#[test]
fn an_unread_request_body_is_skipped_to_keep_the_connection() {
    let proxy = Proxy::start(site(
        json!([{ "respond": { "body": "ignored your body" } }]),
    ));
    let mut client = proxy.client();
    for body in ["with the head", ""] {
        let response = client.roundtrip(&format!(
            "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
        assert_eq!(response.text(), "ignored your body");
    }
    // The body follows its head a moment later.
    client
        .send(b"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\n")
        .unwrap();
    assert_eq!(client.response(false).unwrap().status, 200);
    client.send(b"late..").unwrap();
    assert_eq!(
        client.get("/").text(),
        "ignored your body",
        "the late body was skipped"
    );
}

#[test]
fn an_http_1_0_client_gets_a_body_it_can_read() {
    let origin = Origin::answering(|request| {
        match request.line() {
        "GET /chunked HTTP/1.1" => {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
                .to_vec()
        }
        _ => ok("sized"),
    }
    });
    let proxy = proxy_to(&origin);

    let mut client = proxy.client();
    client
        .send(b"GET /chunked HTTP/1.0\r\nHost: test\r\n\r\n")
        .unwrap();
    let head = client.head().unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert_eq!(support::header(&head, "transfer-encoding"), None);
    assert_eq!(support::header(&head, "connection"), Some("close"));
    assert_eq!(
        client.rest(),
        b"abcdef",
        "chunk syntax removed, ended by the close"
    );

    let mut client = proxy.client();
    client
        .send(b"GET /sized HTTP/1.0\r\nHost: test\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    let kept = client.response(false).unwrap();
    assert_eq!(kept.header("connection"), Some("keep-alive"));
    assert_eq!(kept.text(), "sized");
    client
        .send(b"GET /sized HTTP/1.0\r\nHost: test\r\n\r\n")
        .unwrap();
    assert_eq!(client.response(false).unwrap().text(), "sized");
    assert!(
        client.closed(),
        "HTTP/1.0 closes unless asked to keep alive"
    );
}

#[test]
fn a_close_delimited_origin_does_not_cost_the_client_its_connection() {
    let origin = Origin::start(|stream, _| {
        let mut conn = Client::over(stream);
        conn.request().unwrap();
        conn.send(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil the close")
            .unwrap();
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    for _ in 0..3 {
        let response = client.get("/");
        assert_eq!(response.header("transfer-encoding"), Some("chunked"));
        assert_eq!(response.text(), "until the close");
    }
    assert_eq!(
        origin.connections(),
        3,
        "each such response uses up an origin connection"
    );
}

#[test]
fn an_origin_that_answers_before_the_upload_ends_is_heard() {
    let origin = Origin::start(|stream, _| {
        let mut conn = Client::over(stream);
        // Reads the head only; the body is never read.
        conn.head().unwrap();
        conn.send(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied")
            .unwrap();
        conn.closed();
    });
    let proxy = proxy_to(&origin);
    let mut client = proxy.client();
    let stream = client.stream().try_clone().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    // 64 MiB would fill every socket buffer on the way long before it is all sent.
    let writer = std::thread::spawn({
        let stop = stop.clone();
        move || {
            let mut stream = stream;
            let _ = stream
                .write_all(b"PUT /big HTTP/1.1\r\nHost: test\r\nContent-Length: 67108864\r\n\r\n");
            let piece = payload(64 * 1024);
            for _ in 0..1024 {
                if stop.load(Ordering::Relaxed) || stream.write_all(&piece).is_err() {
                    return;
                }
            }
        }
    });
    let response = client.response(false).expect("the origin's answer");
    assert_eq!((response.status, response.text().as_str()), (403, "denied"));
    assert_eq!(response.header("connection"), Some("close"));
    stop.store(true, Ordering::Relaxed);
    drop(client);
    writer.join().unwrap();
}

#[test]
fn a_request_for_no_site_or_with_a_bad_head_is_refused() {
    let proxy = Proxy::start(json!([
        { "name": "only", "hosts": ["known.test"], "routes": [{ "respond": { "body": "known" } }] }
    ]));
    let mut client = proxy.client();
    assert_eq!(
        client
            .roundtrip("GET / HTTP/1.1\r\nHost: KNOWN.test:80\r\n\r\n")
            .text(),
        "known"
    );
    let unknown = client.roundtrip("GET / HTTP/1.1\r\nHost: other.test\r\n\r\n");
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.header("connection"), Some("close"));
    assert!(client.closed());

    for (request, status) in [
        ("GET / HTTP/1.1\r\n\r\n", 400),
        (
            "GET / HTTP/1.1\r\nHost: known.test\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            400,
        ),
        ("GET / HTTP/2.0\r\nHost: known.test\r\n\r\n", 505),
    ] {
        let mut client = proxy.client();
        let response = client.roundtrip(request);
        assert_eq!(response.status, status, "{request:?}");
        assert_eq!(response.header("connection"), Some("close"));
        assert!(response.header("date").is_some());
        assert!(client.closed());
    }
}

#[test]
fn an_oversized_head_gets_431() {
    let proxy = Proxy::start_with(
        site(json!([{ "respond": { "body": "ok" } }])),
        json!({ "limits": { "maxHeadBytes": 2048, "maxHeaderFields": 8 } }),
    );
    let mut client = proxy.client();
    let long = format!(
        "GET / HTTP/1.1\r\nHost: test\r\nX-Long: {}\r\n\r\n",
        "a".repeat(4096)
    );
    assert_eq!(client.roundtrip(&long).status, 431);

    let mut client = proxy.client();
    let many: String = (0..9).map(|i| format!("X-{i}: v\r\n")).collect();
    let request = format!("GET / HTTP/1.1\r\nHost: test\r\n{many}\r\n");
    assert_eq!(client.roundtrip(&request).status, 431);
}

/// A TLS origin with a self-signed certificate, answering one request per connection.
fn self_signed_origin() -> Origin {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["origin.internal".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    // An origin that prefers HTTP/2 must still be spoken to in HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);
    Origin::start(move |stream, index| {
        let tls = rustls::ServerConnection::new(config.clone()).unwrap();
        let mut stream = rustls::StreamOwned::new(tls, stream);
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                return;
            }
            head.push(byte[0]);
        }
        let mut served = 0;
        loop {
            let alpn = stream.conn.alpn_protocol().map(<[u8]>::to_vec);
            let body = format!(
                "request {served} on TLS connection {index}, alpn {:?}",
                alpn.as_deref().map(String::from_utf8_lossy)
            );
            stream.write_all(&ok(&body)).unwrap();
            served += 1;
            head.clear();
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    return;
                }
                head.push(byte[0]);
            }
        }
    })
}

#[test]
fn an_https_origin_with_a_self_signed_certificate_is_reached_when_verification_is_off() {
    let origin = self_signed_origin();
    let to = format!("https://{}", origin.addr);
    let proxy = Proxy::start_with(
        site(json!([
            { "when": { "path": "/verified" }, "proxy": to },
            { "proxy": { "to": to, "tlsSkipVerify": true } },
        ])),
        json!({ "workers": 1 }),
    );
    let mut client = proxy.client();
    assert_eq!(
        client.get("/").text(),
        "request 0 on TLS connection 0, alpn Some(\"http/1.1\")"
    );
    assert_eq!(
        client.get("/again").text(),
        "request 1 on TLS connection 0, alpn Some(\"http/1.1\")",
        "the TLS connection is pooled"
    );
    assert_eq!(
        client.get("/verified").status,
        502,
        "the same origin fails verification without tlsSkipVerify"
    );
}

#[test]
fn reloads_under_keep_alive_load_lose_no_request() {
    let origin = Origin::answering(|_| ok("from the origin"));
    let sites = |version: usize| {
        json!([{
            "name": "test",
            "hosts": ["*"],
            "headers": { "X-Config": version.to_string() },
            "routes": [
                { "when": { "path": "/local" }, "respond": { "body": "local" } },
                { "proxy": origin.url() },
            ],
        }])
    };
    let proxy = Proxy::start(sites(0));
    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicUsize::new(0));
    let clients: Vec<_> = (0..4)
        .map(|i| {
            let (stop, served) = (stop.clone(), served.clone());
            let mut client = proxy.client();
            std::thread::spawn(move || {
                let mut last = 0;
                while !stop.load(Ordering::Relaxed) {
                    let (path, body) = if i % 2 == 0 {
                        ("/proxied", "from the origin")
                    } else {
                        ("/local", "local")
                    };
                    let response = client.get(path);
                    assert_eq!((response.status, response.text().as_str()), (200, body));
                    let version: usize = response.header("x-config").unwrap().parse().unwrap();
                    assert!(
                        version >= last,
                        "configs never go back: {version} after {last}"
                    );
                    last = version;
                    served.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    const RELOADS: usize = 30;
    let mut probe = proxy.client();
    for version in 1..=RELOADS {
        proxy.rewrite(sites(version));
        let status = proxy.reload();
        assert_eq!(status, format!("serving generation {}", version + 1));
        assert_eq!(
            probe.get("/local").header("x-config"),
            Some(version.to_string().as_str()),
            "the next request on an open connection runs under the new config"
        );
    }
    stop.store(true, Ordering::Relaxed);
    for client in clients {
        client.join().expect("a client saw an error during reloads");
    }
    let served = served.load(Ordering::Relaxed);
    println!("{served} keep-alive requests on 4 connections across {RELOADS} reloads, 0 errors");
    assert!(served > RELOADS, "load ran during the reloads: {served}");
}

/// Load for `strace -f -c` on Linux: `UPSTREAMER_WRAP="strace -f -c -o counts"` wraps the
/// proxy, which serves `UPSTREAMER_STRACE_REQUESTS` keep-alive proxied requests on one core.
#[test]
#[ignore = "run under strace on Linux"]
fn strace_proxied_load() {
    let requests: usize = std::env::var("UPSTREAMER_STRACE_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let origin = Origin::answering(|_| ok("0123456789abcdef"));
    let proxy = Proxy::start_with(
        site(json!([{ "proxy": origin.url() }])),
        json!({ "workers": 1 }),
    );
    let mut client = proxy.client();
    for _ in 0..requests {
        assert_eq!(client.get("/").status, 200);
    }
    drop(client);
    drop(proxy);
    println!(
        "proxied {requests} keep-alive requests over {} origin connection(s)",
        origin.connections()
    );
}
