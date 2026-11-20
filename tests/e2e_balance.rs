//! Load balancing, health checks and retries through the real binary: pools of origins that
//! are threads in the test, one worker so every request sees the same per-core state.

mod support;

use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use support::{Origin, Proxy, closed_addr, eventually, ok, site};

/// One worker: round robin cursors and passive failure counts are per core.
fn one_worker(routes: Value) -> Proxy {
    Proxy::start_with(site(routes), json!({ "workers": 1 }))
}

/// An origin that answers every request with `name`, counting what it served.
fn named(name: &'static str) -> (Origin, Arc<AtomicUsize>) {
    let served = Arc::new(AtomicUsize::new(0));
    let origin = Origin::answering({
        let served = served.clone();
        move |_| {
            served.fetch_add(1, Ordering::SeqCst);
            ok(name)
        }
    });
    (origin, served)
}

fn status(code: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {code} Whatever\r\nContent-Length: {}\r\nX-Origin-Said: {code}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn round_robin_alternates_two_origins_and_weights_split_by_share() {
    let (a, _) = named("a");
    let (b, _) = named("b");
    let proxy = one_worker(json!([
        { "when": { "path": "/even" }, "proxy": { "to": [a.url(), b.url()] } },
        { "proxy": { "to": [{ "url": a.url(), "weight": 3 }, b.url()] } },
    ]));
    let mut client = proxy.client();
    let bodies: Vec<String> = (0..10).map(|_| client.get("/even").text()).collect();
    assert_eq!(bodies.iter().filter(|b| *b == "a").count(), 5, "{bodies:?}");
    assert!(
        bodies.windows(2).all(|w| w[0] != w[1]),
        "round robin alternates: {bodies:?}"
    );
    let weighted: Vec<String> = (0..400).map(|_| client.get("/weighted").text()).collect();
    assert_eq!(weighted.iter().filter(|b| *b == "a").count(), 300);
}

#[test]
fn a_get_moves_to_another_origin_when_one_refuses_connections() {
    let (good, served) = named("good");
    let proxy = one_worker(json!([{ "proxy": {
        "to": [format!("http://{}", closed_addr()), good.url()],
        "health": { "passive": { "maxFails": 0 } },
    } }]));
    let mut client = proxy.client();
    for _ in 0..20 {
        let response = client.get("/");
        assert_eq!((response.status, response.text().as_str()), (200, "good"));
    }
    assert_eq!(served.load(Ordering::SeqCst), 20);
}

#[test]
fn a_post_with_a_body_is_not_retried_on_another_origin() {
    let (good, served) = named("good");
    let proxy = one_worker(json!([{ "proxy": {
        "to": [format!("http://{}", closed_addr()), good.url()],
        "health": { "passive": { "maxFails": 0 } },
    } }]));
    let mut client = proxy.client();
    let statuses: Vec<u16> = (0..10)
        .map(|_| {
            client
                .roundtrip("POST /orders HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nhello")
                .status
        })
        .collect();
    assert_eq!(
        statuses.iter().filter(|&&s| s == 502).count(),
        5,
        "every POST that met the refusing origin fails: {statuses:?}"
    );
    assert_eq!(served.load(Ordering::SeqCst), 5, "and none was sent again");
}

#[test]
fn a_fail_status_is_retried_and_the_last_one_is_passed_through() {
    let counted = |body: &'static str| {
        let served = Arc::new(AtomicUsize::new(0));
        let origin = Origin::answering({
            let served = served.clone();
            move |_| {
                served.fetch_add(1, Ordering::SeqCst);
                status(503, body)
            }
        });
        (origin, served)
    };
    let (busy, busy_served) = counted("busy");
    let (fine, _) = named("fine");
    let (also_busy, also_busy_served) = counted("also busy");
    let proxy = one_worker(json!([
        { "when": { "path": "/one-busy" }, "proxy": {
            "to": [busy.url(), fine.url()],
            "failStatuses": [503],
            "health": { "passive": { "maxFails": 0 } },
        } },
        { "proxy": {
            "to": [busy.url(), also_busy.url()],
            "failStatuses": [503],
            "health": { "passive": { "maxFails": 0 } },
        } },
    ]));
    let mut client = proxy.client();
    for _ in 0..6 {
        let response = client.get("/one-busy");
        assert_eq!((response.status, response.text().as_str()), (200, "fine"));
    }
    let before = busy_served.load(Ordering::SeqCst);
    for _ in 0..4 {
        let response = client.get("/all-busy");
        assert_eq!(response.status, 503);
        assert_eq!(
            response.header("x-origin-said"),
            Some("503"),
            "the origin's response, not an error page"
        );
        assert!(["busy", "also busy"].contains(&response.text().as_str()));
    }
    assert_eq!(
        (
            busy_served.load(Ordering::SeqCst) - before,
            also_busy_served.load(Ordering::SeqCst)
        ),
        (4, 4),
        "each request tried both origins once"
    );
}

#[test]
fn passive_checks_eject_a_refusing_origin_and_readmit_it_after_the_cooldown() {
    let (good, served) = named("good");
    let proxy = one_worker(json!([{ "proxy": {
        "to": [format!("http://{}", closed_addr()), good.url()],
        "retries": 0,
        "health": { "passive": { "maxFails": 2, "cooldown": "3s" } },
    } }]));
    let mut client = proxy.client();
    let first: Vec<u16> = (0..4).map(|_| client.get("/").status).collect();
    assert_eq!(first.iter().filter(|&&s| s == 502).count(), 2, "{first:?}");
    let ejected: Vec<u16> = (0..30).map(|_| client.get("/").status).collect();
    assert!(
        ejected.iter().all(|&s| s == 200),
        "two failures in a row eject it: {ejected:?}"
    );
    std::thread::sleep(Duration::from_millis(3200));
    let readmitted: Vec<u16> = (0..4).map(|_| client.get("/").status).collect();
    assert!(
        readmitted.contains(&502),
        "back in rotation after the cooldown: {readmitted:?}"
    );
    assert!(served.load(Ordering::SeqCst) >= 32);
}

/// An origin answering `name`, whose `/health` passes while `healthy` is set.
fn probed(name: &'static str, healthy: Arc<AtomicBool>) -> Origin {
    Origin::answering(move |request| {
        if request.line().starts_with("GET /health ") {
            if healthy.load(Ordering::SeqCst) {
                ok("up")
            } else {
                status(503, "down")
            }
        } else {
            ok(name)
        }
    })
}

#[test]
fn an_active_check_takes_a_failing_origin_out_and_brings_it_back() {
    let healthy = Arc::new(AtomicBool::new(true));
    let a = probed("a", healthy.clone());
    let (b, _) = named("b");
    let proxy = one_worker(json!([{ "proxy": {
        "to": [a.url(), b.url()],
        "health": { "active": {
            "path": "/health", "interval": "200ms", "healthyAfter": 1, "unhealthyAfter": 2,
        } },
    } }]));
    let client = std::cell::RefCell::new(proxy.client());
    let all_b = || (0..6).all(|_| client.borrow_mut().get("/").text() == "b");
    assert!(!all_b(), "both serve while both pass");
    healthy.store(false, Ordering::SeqCst);
    eventually("the failing origin leaves the rotation", all_b);
    healthy.store(true, Ordering::SeqCst);
    eventually("the origin comes back once it passes", || {
        (0..4).any(|_| client.borrow_mut().get("/").text() == "a")
    });
}

#[test]
fn a_pool_with_no_origin_left_answers_503_with_retry_after_through_an_error_route() {
    let healthy = Arc::new(AtomicBool::new(false));
    let only = probed("only", healthy);
    let proxy = Proxy::start_with(
        json!([{
            "name": "test",
            "hosts": ["*"],
            "routes": [{ "proxy": {
                "to": [only.url()],
                "health": { "active": { "path": "/health", "interval": "2s", "unhealthyAfter": 1 } },
            } }],
            "errors": [{ "status": [503], "routes": [
                { "respond": { "status": 503, "body": "down, retry in {err.retry_after}s" } },
            ] }],
        }]),
        json!({ "workers": 1 }),
    );
    let client = std::cell::RefCell::new(proxy.client());
    eventually("the only origin fails its check", || {
        client.borrow_mut().get("/").status == 503
    });
    let response = client.borrow_mut().get("/");
    assert_eq!(response.status, 503);
    assert_eq!(response.text(), "down, retry in 2s");
    assert_eq!(
        response.header("retry-after"),
        Some("2"),
        "one probe interval"
    );
}

#[test]
fn a_hash_key_keeps_each_client_on_one_origin() {
    let origins: Vec<Origin> = ["a", "b", "c"].iter().map(|n| named(n).0).collect();
    let proxy = Proxy::start(site(json!([{ "proxy": {
        "to": origins.iter().map(Origin::url).collect::<Vec<_>>(),
        "balance": { "hash": "{header.x-user}" },
    } }])));
    let mut seen = std::collections::HashSet::new();
    for user in 0..30 {
        let request = format!("GET / HTTP/1.1\r\nHost: test\r\nX-User: user-{user}\r\n\r\n");
        let mut answers = std::collections::HashSet::new();
        for _ in 0..5 {
            answers.insert(proxy.client().roundtrip(&request).text());
        }
        assert_eq!(
            answers.len(),
            1,
            "user-{user} on every connection: {answers:?}"
        );
        seen.extend(answers);
    }
    assert_eq!(seen.len(), 3, "keys spread over the origins: {seen:?}");
}

#[test]
fn least_requests_and_p2c_send_to_every_origin() {
    let (a, served_a) = named("a");
    let (b, served_b) = named("b");
    let proxy = one_worker(json!([
        { "when": { "path": "/least" },
          "proxy": { "to": [a.url(), b.url()], "balance": "leastRequests" } },
        { "proxy": { "to": [a.url(), b.url()], "balance": "p2c" } },
    ]));
    let mut client = proxy.client();
    for path in ["/least", "/p2c"] {
        let (before_a, before_b) = (
            served_a.load(Ordering::SeqCst),
            served_b.load(Ordering::SeqCst),
        );
        for _ in 0..200 {
            assert_eq!(client.get(path).status, 200);
        }
        let a = served_a.load(Ordering::SeqCst) - before_a;
        let b = served_b.load(Ordering::SeqCst) - before_b;
        assert_eq!(a + b, 200);
        assert!(a > 40 && b > 40, "{path}: {a} and {b}");
    }
}
