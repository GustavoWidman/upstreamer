//! Rate limits through the real binary: the 429 a limited client reads on the wire, how the
//! error route sees the refusal, and buckets shared by every core and kept across reloads.

mod support;

use serde_json::{Value, json};
use std::time::Duration;
use support::{Proxy, Response, site};

/// A site that limits by the `X-Client` header and answers `body` otherwise; a 429 is answered
/// by an error route that quotes `{err.retry_after}`.
fn limited(limit: Value, body: &str) -> Value {
    json!([{
        "name": "limited",
        "hosts": ["*"],
        "routes": [
            { "limit": limit },
            { "respond": { "body": body } },
        ],
        "errors": [{ "status": [429], "routes": [
            { "respond": { "status": 429, "body": "slow down {err.retry_after}" } },
        ]}],
    }])
}

fn get_as(client: &mut support::Client, who: &str) -> Response {
    client.roundtrip(&format!(
        "GET / HTTP/1.1\r\nHost: test\r\nX-Client: {who}\r\n\r\n"
    ))
}

fn per_client(rate: &str, burst: u32) -> Value {
    json!({ "rate": rate, "burst": burst, "key": "{header.x-client}" })
}

#[test]
fn a_client_over_its_burst_gets_429_with_retry_after_and_the_error_route_sees_it() {
    let proxy = Proxy::start(limited(per_client("1/h", 3), "ok"));
    let mut client = proxy.client();
    for n in 1..=3 {
        let response = get_as(&mut client, "a");
        assert_eq!(response.status, 200, "request {n} is inside the burst");
        assert_eq!(response.text(), "ok");
        assert_eq!(response.header("retry-after"), None);
    }
    let refused = get_as(&mut client, "a");
    assert_eq!(refused.status, 429, "{}", refused.head);
    assert_eq!(
        refused.header("retry-after"),
        Some("3600"),
        "one interval of an hourly rate: {}",
        refused.head
    );
    assert_eq!(refused.text(), "slow down 3600");
    let again = get_as(&mut client, "a");
    assert_eq!(again.status, 429, "hammering does not reopen the bucket");
}

#[test]
fn clients_have_buckets_of_their_own_and_a_request_without_a_key_is_never_limited() {
    let proxy = Proxy::start(limited(per_client("1/h", 1), "ok"));
    let mut client = proxy.client();
    assert_eq!(get_as(&mut client, "a").status, 200);
    assert_eq!(get_as(&mut client, "a").status, 429);
    assert_eq!(
        get_as(&mut client, "b").status,
        200,
        "another key, another bucket"
    );
    assert_eq!(get_as(&mut client, "b").status, 429);
    for _ in 0..5 {
        assert_eq!(
            client.get("/").status,
            200,
            "no X-Client header, no key, no bucket"
        );
    }
}

#[test]
fn every_connection_draws_on_the_same_bucket() {
    let proxy = Proxy::start(limited(per_client("1/h", 5), "ok"));
    let mut clients: Vec<_> = (0..8).map(|_| proxy.client()).collect();
    let mut admitted = 0;
    for _ in 0..3 {
        for client in &mut clients {
            if get_as(client, "shared").status == 200 {
                admitted += 1;
            }
        }
    }
    assert_eq!(
        admitted, 5,
        "24 requests over 8 connections admit the burst, no more"
    );
}

#[test]
fn the_default_key_is_the_clients_network() {
    let proxy = Proxy::start(site(json!([
        { "limit": { "rate": "1/h", "burst": 2 } },
        { "respond": { "body": "ok" } },
    ])));
    let statuses: Vec<u16> = (0..4).map(|_| proxy.client().get("/").status).collect();
    assert_eq!(
        statuses,
        [200, 200, 429, 429],
        "new connections, one bucket"
    );
}

#[test]
fn a_refused_client_is_admitted_again_after_the_wait_it_was_told() {
    let proxy = Proxy::start(limited(per_client("5/s", 1), "ok"));
    let mut client = proxy.client();
    assert_eq!(get_as(&mut client, "a").status, 200);
    let refused = get_as(&mut client, "a");
    assert_eq!(refused.status, 429);
    assert_eq!(refused.header("retry-after"), Some("1"));
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        get_as(&mut client, "a").status,
        200,
        "a fifth of a second is one interval at 5/s"
    );
}

#[test]
fn only_the_steps_that_guard_a_limit_are_limited() {
    let proxy = Proxy::start(site(json!([
        { "when": { "path": "/api" }, "limit": { "rate": "1/h", "burst": 1, "key": "all" } },
        { "respond": { "body": "ok" } },
    ])));
    let mut client = proxy.client();
    assert_eq!(client.get("/api").status, 200);
    assert_eq!(client.get("/api").status, 429);
    assert_eq!(
        client.get("/other").status,
        200,
        "the limit's `when` does not match"
    );
}

#[test]
fn a_reload_keeps_the_buckets_of_an_unchanged_limit_and_resets_a_changed_one() {
    let proxy = Proxy::start(limited(per_client("1/h", 1), "v1"));
    let mut client = proxy.client();
    assert_eq!(get_as(&mut client, "a").status, 200);
    assert_eq!(get_as(&mut client, "a").status, 429);

    proxy.rewrite(limited(per_client("1/h", 1), "v2"));
    proxy.reload();
    let mut client = proxy.client();
    assert_eq!(
        get_as(&mut client, "a").status,
        429,
        "the same site, step and key keep their bucket across the reload"
    );

    proxy.rewrite(limited(
        json!({ "rate": "1/h", "burst": 1, "key": "{header.x-client}-v3" }),
        "v3",
    ));
    proxy.reload();
    let mut client = proxy.client();
    let response = get_as(&mut client, "a");
    assert_eq!(
        (response.status, response.text().as_str()),
        (200, "v3"),
        "a different key template starts empty, on the new config"
    );
}
