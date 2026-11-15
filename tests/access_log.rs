//! Access logs through the real binary: one JSON line per request on HTTP/1.1, HTTP/2 and
//! HTTP/3 and per WebSocket tunnel, nothing for a site without a log, a new file after a
//! rename and a reload, and only whole lines when every core writes at once.

mod support;

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use support::clients::{H2, H3, reserve_udp};
use support::{Client, Origin, Proxy, eventually, ok};

/// A plain site for `host` that logs to `log` (when given) and runs `routes`.
fn site(host: &str, log: Option<&Path>, routes: Value) -> Value {
    let mut site = json!({ "name": host, "hosts": [host], "routes": routes });
    if let Some(log) = log {
        site["accessLog"] = json!(log);
    }
    site
}

fn hello() -> Value {
    json!([{ "respond": { "body": "hello" } }])
}

/// The log's lines, each parsed. Every line must be a whole JSON object.
fn lines(path: &Path) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "a cut line: {text:?}"
    );
    text.lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON line: {e}: {line}"))
        })
        .collect()
}

/// Waits until the log has `n` lines (the cores write at least once a second) and returns them.
fn wait_lines(path: &Path, n: usize) -> Vec<Value> {
    eventually(&format!("{n} lines in {}", path.display()), || {
        lines(path).len() >= n
    });
    let lines = lines(path);
    assert_eq!(lines.len(), n, "{lines:#?}");
    lines
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn is_timestamp(ts: &Value) -> bool {
    let Some(ts) = ts.as_str() else { return false };
    let shape = b"dddd-dd-ddTdd:dd:dd.dddZ";
    ts.len() == shape.len()
        && ts.bytes().zip(shape).all(|(b, &s)| match s {
            b'd' => b.is_ascii_digit(),
            s => b == s,
        })
}

fn logs() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("access.log");
    (dir, path)
}

#[test]
fn h1_requests_are_logged_and_a_site_without_a_log_writes_nothing() {
    let (dir, path) = logs();
    let proxy = Proxy::start(json!([
        site("logged.test", Some(&path), hello()),
        site("quiet.test", None, hello()),
    ]));
    let mut client = proxy.client();
    let mut request = b"GET /a%20b?x=\"1\" HTTP/1.1\r\nHost: Logged.Test:8080\r\n".to_vec();
    request.extend_from_slice(b"User-Agent: agent \"q\" \\ \xff end\r\n\r\n");
    client.send(&request).unwrap();
    assert_eq!(client.response(false).unwrap().text(), "hello");
    let head = client.roundtrip(
        "HEAD /h HTTP/1.1\r\nHost: logged.test\r\nReferer: https://example.com/p\r\n\r\n",
    );
    assert_eq!(head.status, 200);
    for _ in 0..3 {
        let mut quiet = proxy.client();
        let reply = quiet.roundtrip("GET / HTTP/1.1\r\nHost: quiet.test\r\n\r\n");
        assert_eq!(reply.text(), "hello");
    }

    let lines = wait_lines(&path, 2);
    let port = client.stream().local_addr().unwrap().port();
    let get = &lines[0];
    assert!(is_timestamp(&get["ts"]), "{get}");
    let duration = get["duration"].as_f64().unwrap();
    assert!((0.0..5.0).contains(&duration), "{get}");
    assert_eq!(
        get,
        &json!({
            "ts": get["ts"],
            "remote_ip": "127.0.0.1",
            "remote_port": port,
            "host": "logged.test",
            "method": "GET",
            "target": "/a%20b?x=\"1\"",
            "proto": "HTTP/1.1",
            "user_agent": "agent \"q\" \\ \u{fffd} end",
            "referer": null,
            "status": 200,
            "bytes": 5,
            "duration": get["duration"],
            "upstream": null,
        })
    );
    let head = &lines[1];
    assert_eq!(head["method"], "HEAD");
    assert_eq!(head["target"], "/h");
    assert_eq!(head["referer"], "https://example.com/p");
    assert_eq!(head["user_agent"], Value::Null);
    assert_eq!(head["bytes"], 0, "a HEAD response has no body");

    drop(proxy);
    let files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(files, ["access.log"], "the quiet site wrote no file");
    assert_eq!(lines_of(&path), 2, "and no line in the other");
}

fn lines_of(path: &Path) -> usize {
    lines(path).len()
}

#[test]
fn a_proxied_request_names_its_origin_and_the_target_as_received() {
    let origin = Origin::answering(|_| ok("0123456789"));
    let (_dir, path) = logs();
    let proxy = Proxy::start(json!([site(
        "test",
        Some(&path),
        json!([{ "stripPrefix": "/api" }, { "proxy": origin.url() }]),
    )]));
    let reply = proxy.client().get("/api/items?page=2");
    assert_eq!(reply.text(), "0123456789");
    let line = &wait_lines(&path, 1)[0];
    assert_eq!(line["target"], "/api/items?page=2");
    assert_eq!(line["status"], 200);
    assert_eq!(line["bytes"], 10);
    assert_eq!(line["upstream"], origin.addr.to_string());
}

#[test]
fn an_unreachable_origin_is_logged_with_its_status_and_origin() {
    let closed = support::closed_addr();
    let (_dir, path) = logs();
    let proxy = Proxy::start(json!([site(
        "test",
        Some(&path),
        json!([{ "proxy": format!("http://{closed}") }]),
    )]));
    assert_eq!(proxy.client().get("/").status, 502);
    let line = &wait_lines(&path, 1)[0];
    assert_eq!(line["status"], 502);
    assert_eq!(line["upstream"], closed.to_string());
}

#[test]
fn h2_and_h3_requests_are_logged_with_their_protocol() {
    let port = reserve_udp();
    let (_dir, path) = logs();
    let host = "tls.test";
    let proxy = Proxy::start(json!([{
        "name": host,
        "hosts": [host],
        "listen": [port.addr],
        "tls": {
            "cert": "/nonexistent/tls.crt",
            "key": "/nonexistent/tls.key",
            "redirectHttp": false,
            "http3": true,
        },
        "accessLog": path,
        "routes": hello(),
    }]));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut h2 = H2::connect(port.addr, host).await.unwrap();
        assert_eq!(h2.get("/over-h2?a=1").await.unwrap().text(), "hello");
        let mut h3 = H3::connect(port.addr, host).await.unwrap();
        assert_eq!(h3.get("/over-h3").await.unwrap().text(), "hello");
    });
    drop(proxy);

    let lines = lines(&path);
    let by_proto = |proto: &str| -> &Value {
        lines
            .iter()
            .find(|l| l["proto"] == proto)
            .unwrap_or_else(|| panic!("no {proto} line in {lines:#?}"))
    };
    let (h2, h3) = (by_proto("HTTP/2"), by_proto("HTTP/3"));
    assert_eq!(lines.len(), 2, "{lines:#?}");
    assert_eq!(h2["target"], "/over-h2?a=1");
    assert_eq!(h3["target"], "/over-h3");
    for line in [h2, h3] {
        assert_eq!(line["host"], host);
        assert_eq!(line["method"], "GET");
        assert_eq!(line["status"], 200);
        assert_eq!(line["bytes"], 5);
        assert_eq!(line["remote_ip"], "127.0.0.1");
        assert!(is_timestamp(&line["ts"]), "{line}");
    }
}

#[test]
fn a_websocket_tunnel_is_logged_once_it_closes() {
    let origin = Origin::start(|stream, _| {
        let mut conn = Client::over(stream);
        let request = conn.request().unwrap();
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
    let (_dir, path) = logs();
    let proxy = Proxy::start(json!([site(
        "test",
        Some(&path),
        json!([{ "proxy": origin.url() }]),
    )]));
    let mut client = proxy.client();
    client
        .send(
            b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .unwrap();
    assert!(client.head().unwrap().starts_with("HTTP/1.1 101 "));
    client
        .send(&support::websocket_frame(1, b"hello", Some([1, 2, 3, 4])))
        .unwrap();
    assert_eq!(
        support::read_websocket_frame(&mut client),
        (1, b"hello".to_vec())
    );
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert_eq!(
        lines_of(&path),
        0,
        "nothing is logged while the tunnel is open"
    );
    client
        .send(&support::websocket_frame(8, b"", Some([1, 2, 3, 4])))
        .unwrap();
    assert_eq!(support::read_websocket_frame(&mut client), (8, Vec::new()));
    drop(client);

    let line = &wait_lines(&path, 1)[0];
    assert_eq!(line["status"], 101);
    assert_eq!(line["target"], "/ws");
    assert_eq!(line["upstream"], origin.addr.to_string());
    assert_eq!(
        line["bytes"], 9,
        "the two frames relayed to the client: 2 + 5 and 2 bytes"
    );
    assert!(line["duration"].as_f64().unwrap() >= 1.5, "{line}");
}

#[test]
fn a_reload_after_a_rename_starts_a_new_file() {
    let (dir, path) = logs();
    let proxy = Proxy::start(json!([site("test", Some(&path), hello())]));
    proxy.client().get("/before");
    wait_lines(&path, 1);
    let rotated = dir.path().join("access.log.1");
    std::fs::rename(&path, &rotated).unwrap();
    assert_eq!(proxy.reload(), "serving generation 2");
    proxy.client().get("/after");

    let after = wait_lines(&path, 1);
    assert_eq!(after[0]["target"], "/after");
    let before = lines(&rotated);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0]["target"], "/before");
}

#[test]
fn a_log_that_cannot_be_opened_is_reported_and_the_reload_still_applies() {
    let (dir, path) = logs();
    let proxy = Proxy::start(json!([site("test", Some(&path), hello())]));
    let missing = dir.path().join("no-such-dir").join("access.log");
    proxy.rewrite(json!([site(
        "test",
        Some(&missing),
        json!([{ "respond": { "body": "v2" } }]),
    )]));
    assert_eq!(
        proxy.reload(),
        format!(
            "serving generation 2; cannot open access log {}: No such file or directory (os error 2)",
            missing.display()
        )
    );
    assert_eq!(proxy.client().get("/").text(), "v2");
    proxy.rewrite(json!([site("test", Some(&path), hello())]));
    assert_eq!(proxy.reload(), "serving generation 3");
    proxy.client().get("/logged-again");
    assert_eq!(wait_lines(&path, 1)[0]["target"], "/logged-again");
}

#[test]
fn a_burst_from_every_core_writes_only_whole_lines() {
    let (_dir, path) = logs();
    let proxy = Proxy::start_with(
        json!([site("test", Some(&path), hello())]),
        json!({ "workers": 4 }),
    );
    let addr: SocketAddr = proxy.addr;
    // Long lines fill a core's buffer every four requests, so the cores write often and, where
    // the kernel spreads connections over SO_REUSEPORT sockets (Linux), at the same time.
    let agent = "a".repeat(8000);
    let (clients, requests) = (32, 200);
    let threads: Vec<_> = (0..clients)
        .map(|c| {
            let agent = agent.clone();
            std::thread::spawn(move || {
                let mut client = Client::connect(addr);
                for i in 0..requests {
                    let reply = client.roundtrip(&format!(
                        "GET /{c}/{i} HTTP/1.1\r\nHost: test\r\nUser-Agent: {agent}\r\n\r\n"
                    ));
                    assert_eq!(reply.status, 200);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    drop(proxy);

    let lines = lines(&path);
    let targets: BTreeSet<String> = lines
        .iter()
        .map(|l| {
            assert_eq!(l["user_agent"], agent.as_str());
            l["target"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(lines.len(), clients * requests);
    assert_eq!(targets.len(), clients * requests, "each request once");
}
