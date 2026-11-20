//! The `metrics` step through the real binary: what a scrape returns, checked by Prometheus's
//! own `promtool`, and counts that stay exact while the config reloads under load.
//!
//! `promtool` is taken from `PROMTOOL`, else from `PATH`. Without it the exposition is still
//! checked here, and the promtool check is skipped unless `UPSTREAMER_REQUIRE_PROMTOOL` is
//! set, as the flake check sets it.

mod support;

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use support::{Client, Origin, Proxy, ok, site};

fn routes(origin: &Origin, web: &str) -> Value {
    site(json!([
        { "name": "scrape", "when": { "path": "/metrics" }, "metrics": {} },
        { "name": "api", "when": { "path": "/api" }, "proxy": origin.url() },
        { "name": web, "respond": { "body": "ok" } },
    ]))
}

/// The scrape's body, after checking its status and content type.
fn scrape(client: &mut Client) -> String {
    let response = client.get("/metrics");
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(
        response.header("content-type"),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    response.text()
}

/// The sum of the samples of `name` whose label text contains every one of `labels`.
fn sum(text: &str, name: &str, labels: &[&str]) -> u64 {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.rsplit_once(' '))
        .filter(|(series, _)| {
            let family = series.split('{').next().unwrap_or_default();
            family == name && labels.iter().all(|l| series.contains(l))
        })
        .map(|(_, value)| value.parse::<f64>().expect("a number") as u64)
        .sum()
}

fn promtool() -> Option<String> {
    if let Ok(path) = std::env::var("PROMTOOL") {
        return Some(path);
    }
    let found = Command::new("promtool")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    found.then(|| "promtool".to_owned())
}

#[test]
fn the_exposition_passes_promtool() {
    let origin = Origin::answering(|_| ok("from origin"));
    let proxy = Proxy::start(routes(&origin, "web"));
    let mut client = proxy.client();
    for path in ["/api", "/", "/", "/api", "/nothing"] {
        assert_eq!(client.get(path).status, 200);
    }
    proxy.rewrite(routes(&origin, "web2"));
    proxy.reload();
    client.get("/");
    let text = scrape(&mut client);
    assert_eq!(sum(&text, "upstreamer_config_generation", &[]), 2);
    assert_eq!(
        sum(&text, "upstreamer_config_reloads_total", &["result=\"ok\""]),
        1
    );
    for family in [
        "upstreamer_requests_total counter",
        "upstreamer_request_duration_seconds histogram",
        "upstreamer_upstream_responses_total counter",
        "upstreamer_connections_total counter",
        "process_cpu_seconds_total counter",
    ] {
        assert!(text.contains(&format!("# TYPE {family}\n")), "{text}");
    }

    let Some(promtool) = promtool() else {
        assert!(
            std::env::var_os("UPSTREAMER_REQUIRE_PROMTOOL").is_none(),
            "promtool is required and not found"
        );
        eprintln!("promtool not found; skipping `promtool check metrics`");
        return;
    };
    let mut check = Command::new(promtool)
        .args(["check", "metrics"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("promtool starts");
    check
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let output = check.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "promtool check metrics: {}{}\n{text}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn counts_stay_exact_while_four_clients_run_through_fifty_reloads() {
    let origin = Origin::answering(|_| ok("from origin"));
    let proxy = Proxy::start(routes(&origin, "web0"));
    let running = Arc::new(AtomicBool::new(true));
    let completed = Arc::new(AtomicU64::new(0));
    let clients: Vec<_> = (0..4u64)
        .map(|i| {
            let (running, completed) = (running.clone(), completed.clone());
            let addr = proxy.addr;
            std::thread::spawn(move || {
                let mut client = Client::connect(addr);
                let mut n = 0u64;
                while running.load(Ordering::Relaxed) {
                    let path = if (n + i).is_multiple_of(4) {
                        "/api"
                    } else {
                        "/"
                    };
                    assert_eq!(client.get(path).status, 200);
                    completed.fetch_add(1, Ordering::Relaxed);
                    n += 1;
                    if n.is_multiple_of(101) {
                        client = Client::connect(addr);
                    }
                }
            })
        })
        .collect();
    for reload in 1..=50 {
        proxy.rewrite(routes(&origin, &format!("web{}", reload % 3)));
        let status = proxy.reload();
        assert!(status.starts_with("serving generation"), "{status}");
    }
    running.store(false, Ordering::Relaxed);
    for client in clients {
        client.join().unwrap();
    }
    std::thread::sleep(Duration::from_millis(1_500));
    let text = scrape(&mut proxy.client());
    let completed = completed.load(Ordering::Relaxed);
    assert!(completed > 200, "the clients ran: {completed}");
    assert_eq!(
        sum(&text, "upstreamer_requests_total", &[]),
        completed,
        "every completed request counted once\n{text}"
    );
    assert_eq!(
        sum(&text, "upstreamer_config_reloads_total", &["result=\"ok\""]),
        50
    );
    assert_eq!(sum(&text, "upstreamer_config_generation", &[]), 51);
}
