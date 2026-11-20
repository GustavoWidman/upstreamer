//! Trusted proxies through the real binary: the client address a trusted peer forwards
//! reaches `{remote_host}`, the access log and the `X-Forwarded-For` the origin reads, while
//! an untrusted peer's headers change nothing. Every test connects from 127.0.0.1.

mod support;

use serde_json::{Value, json};
use std::path::Path;
use support::clients::{H2, reserve_udp};
use support::{Origin, Proxy, eventually, ok};

/// A proxy that forwards to `origin`, naming the client and the peer in headers the origin
/// echoes back, and trusting `from` for `header`.
fn proxy(origin: &Origin, from: &[&str], header: &str) -> Proxy {
    Proxy::start_with(
        json!([{
            "name": "test",
            "hosts": ["*"],
            "routes": [{ "proxy": {
                "to": origin.url(),
                "headers": { "X-Client": "{remote_host}", "X-Peer": "{peer_host}" },
            } }],
        }]),
        json!({ "trustedProxies": { "from": from, "header": header } }),
    )
}

fn echo() -> Origin {
    Origin::answering(|request| ok(&request.head))
}

/// What the origin saw: `(x-client, x-peer, x-forwarded-for)` for a request carrying `headers`.
fn seen_by_origin(proxy: &Proxy, headers: &[(&str, &str)]) -> (String, String, String) {
    let mut request = String::from("GET / HTTP/1.1\r\nHost: test\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    let response = proxy.client().roundtrip(&request);
    assert_eq!(response.status, 200);
    let head = response.text();
    let field = |name| {
        support::header(&head, name)
            .unwrap_or("<absent>")
            .to_owned()
    };
    (field("x-client"), field("x-peer"), field("x-forwarded-for"))
}

fn text((a, b, c): (&str, &str, &str)) -> (String, String, String) {
    (a.into(), b.into(), c.into())
}

#[test]
fn a_trusted_peers_cf_connecting_ip_is_the_client() {
    let origin = echo();
    let proxy = proxy(&origin, &["127.0.0.0/8"], "CF-Connecting-IP");
    assert_eq!(
        seen_by_origin(
            &proxy,
            &[
                ("CF-Connecting-IP", "198.51.100.23"),
                ("X-Forwarded-For", "198.51.100.23, 10.1.1.1"),
            ]
        ),
        text((
            "198.51.100.23",
            "127.0.0.1",
            "198.51.100.23, 10.1.1.1, 127.0.0.1"
        )),
        "the client replaces {{remote_host}}, {{peer_host}} stays the peer, the peer is appended to the chain"
    );
    assert_eq!(
        seen_by_origin(&proxy, &[("CF-Connecting-IP", "2001:db8::7")]),
        text(("2001:db8::7", "127.0.0.1", "127.0.0.1")),
        "an IPv6 client"
    );
    assert_eq!(
        seen_by_origin(&proxy, &[("CF-Connecting-IP", "::ffff:198.51.100.23")]),
        text(("198.51.100.23", "127.0.0.1", "127.0.0.1")),
        "a mapped client is the IPv4 address"
    );
}

#[test]
fn a_trusted_peer_that_sends_no_usable_address_is_its_own_client() {
    let origin = echo();
    let proxy = proxy(&origin, &["127.0.0.0/8"], "CF-Connecting-IP");
    for headers in [
        &[][..],
        &[("CF-Connecting-IP", "not-an-ip")],
        &[("CF-Connecting-IP", "198.51.100.23, 198.51.100.24")],
        &[("X-Real-IP", "198.51.100.23")],
    ] {
        assert_eq!(
            seen_by_origin(&proxy, headers),
            text(("127.0.0.1", "127.0.0.1", "127.0.0.1")),
            "{headers:?}"
        );
    }
}

#[test]
fn an_untrusted_peers_headers_change_nothing() {
    let origin = echo();
    for header in ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"] {
        let proxy = proxy(&origin, &["10.0.0.0/8", "2001:db8::/32"], header);
        assert_eq!(
            seen_by_origin(
                &proxy,
                &[
                    ("CF-Connecting-IP", "198.51.100.23"),
                    ("X-Forwarded-For", "10.0.0.1, 198.51.100.23"),
                    ("X-Real-IP", "198.51.100.23"),
                ]
            ),
            text(("127.0.0.1", "127.0.0.1", "127.0.0.1")),
            "{header}: the origin must not read an address the client chose"
        );
    }
}

#[test]
fn x_forwarded_for_gives_its_rightmost_untrusted_address() {
    let origin = echo();
    let proxy = proxy(&origin, &["127.0.0.0/8", "10.0.0.0/8"], "X-Forwarded-For");
    assert_eq!(
        seen_by_origin(
            &proxy,
            &[("X-Forwarded-For", "1.1.1.1, 198.51.100.23, 10.0.0.9")]
        ),
        text((
            "198.51.100.23",
            "127.0.0.1",
            "1.1.1.1, 198.51.100.23, 10.0.0.9, 127.0.0.1"
        )),
    );
    assert_eq!(
        seen_by_origin(
            &proxy,
            &[
                ("X-Forwarded-For", "198.51.100.23, 10.0.0.9"),
                ("X-Forwarded-For", "10.0.0.10")
            ]
        )
        .0,
        "198.51.100.23",
        "the chain may span fields"
    );
    assert_eq!(
        seen_by_origin(&proxy, &[("X-Forwarded-For", "198.51.100.23, junk")]).0,
        "127.0.0.1",
        "an unreadable entry nearest the trusted peer is not skipped to reach an earlier one"
    );
}

#[test]
fn x_real_ip_is_the_client_of_a_trusted_peer() {
    let origin = echo();
    let proxy = proxy(&origin, &["127.0.0.1"], "x-real-ip");
    assert_eq!(
        seen_by_origin(&proxy, &[("X-Real-IP", "198.51.100.23")]).0,
        "198.51.100.23"
    );
}

#[test]
fn without_trusted_proxies_the_peer_is_the_client() {
    let origin = echo();
    let proxy = Proxy::start(support::site(json!([{
        "proxy": {
            "to": origin.url(),
            "headers": { "X-Client": "{remote_host}", "X-Peer": "{peer_host}" },
        }
    }])));
    assert_eq!(
        seen_by_origin(
            &proxy,
            &[
                ("CF-Connecting-IP", "198.51.100.23"),
                ("X-Forwarded-For", "198.51.100.23"),
            ]
        ),
        text(("127.0.0.1", "127.0.0.1", "127.0.0.1"))
    );
}

fn log_lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn the_access_log_names_the_forwarded_client() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("access.log");
    let proxy = Proxy::start_with(
        json!([{
            "name": "test",
            "hosts": ["*"],
            "accessLog": path,
            "routes": [{ "respond": { "body": "hello" } }],
        }]),
        json!({ "trustedProxies": { "from": ["127.0.0.0/8"], "header": "CF-Connecting-IP" } }),
    );
    let mut client = proxy.client();
    client.roundtrip("GET /a HTTP/1.1\r\nHost: test\r\nCF-Connecting-IP: 198.51.100.23\r\n\r\n");
    client.roundtrip("GET /b HTTP/1.1\r\nHost: test\r\n\r\n");
    eventually("two log lines", || log_lines(&path).len() == 2);
    let lines = log_lines(&path);
    let remote = |target: &str| {
        lines
            .iter()
            .find(|l| l["target"] == target)
            .unwrap_or_else(|| panic!("{lines:#?}"))["remote_ip"]
            .clone()
    };
    assert_eq!(remote("/a"), "198.51.100.23");
    assert_eq!(remote("/b"), "127.0.0.1", "no header: the peer");
}

#[test]
fn http2_requests_resolve_the_client_too() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("access.log");
    let port = reserve_udp();
    let host = "tls.test";
    let proxy = Proxy::start_with(
        json!([{
            "name": host,
            "hosts": [host],
            "listen": [port.addr],
            "tls": { "cert": "/nonexistent/tls.crt", "key": "/nonexistent/tls.key", "redirectHttp": false, "http3": false },
            "accessLog": path,
            "routes": [{ "respond": { "body": "hello" } }],
        }]),
        json!({ "trustedProxies": { "from": ["127.0.0.0/8"], "header": "X-Forwarded-For" } }),
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut h2 = H2::connect(port.addr, host).await.unwrap();
        for (target, forwarded) in [
            ("/spoofed", "9.9.9.9, 198.51.100.23, 127.0.0.2"),
            ("/plain", ""),
        ] {
            std::future::poll_fn(|cx| h2.send.poll_ready(cx))
                .await
                .unwrap();
            let mut request = http::Request::get(format!("https://{host}{target}"));
            if !forwarded.is_empty() {
                request = request.header("x-forwarded-for", forwarded);
            }
            let (response, _) = h2
                .send
                .send_request(request.body(()).unwrap(), true)
                .unwrap();
            assert_eq!(response.await.unwrap().status(), 200);
        }
    });
    drop(proxy);
    let lines = log_lines(&path);
    let remote = |target: &str| {
        lines
            .iter()
            .find(|l| l["target"] == target)
            .unwrap_or_else(|| panic!("{lines:#?}"))["remote_ip"]
            .clone()
    };
    assert_eq!(remote("/spoofed"), "198.51.100.23");
    assert_eq!(remote("/plain"), "127.0.0.1");
}
