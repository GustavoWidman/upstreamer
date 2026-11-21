//! h2spec (summerwind/h2spec), the HTTP/2 conformance suite, against the real binary over TLS
//! with ALPN h2: every case, strict ones included, on a route the proxy answers itself and on
//! a route proxied to an HTTP/1.1 origin.
//!
//! h2spec is taken from `H2SPEC`, else from `PATH`. Without it the test skips, unless
//! `UPSTREAMER_REQUIRE_H2SPEC` is set, as CI sets it.

mod support;

use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use support::{Origin, Proxy, Reserved};

/// Cases (`<spec>/<section>/<n>`, as h2spec numbers them) that may fail, each with the RFC
/// 9113 or RFC 7541 text that makes the expected behaviour wrong. A listed case that passes
/// fails the test, so the list holds only what still differs.
const EXCLUDED: &[(&str, &str)] = &[];

/// Larger than the 65,535-byte initial flow-control window, so the WINDOW_UPDATE cases
/// (RFC 9113 section 6.9) see the response stall and resume.
const BODY_LEN: usize = 128 * 1024;

/// h2spec waits this long for each expected frame before it fails the case.
const CASE_TIMEOUT_SECS: &str = "5";

fn h2spec() -> Option<String> {
    if let Ok(path) = std::env::var("H2SPEC") {
        return Some(path);
    }
    let found = Command::new("h2spec")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    found.then(|| "h2spec".to_owned())
}

/// An origin that drains each request's body, then answers with `BODY_LEN` bytes. A
/// connection the proxy abandons mid-request (h2spec resets streams) only ends its thread.
fn origin() -> Origin {
    Origin::start(|stream, _| {
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY_LEN}\r\n\r\n");
        let body = vec![b'o'; BODY_LEN];
        while let Some(head_only) = drain_request(&mut reader) {
            let sent = writer.write_all(head.as_bytes()).and_then(|()| {
                if head_only {
                    Ok(())
                } else {
                    writer.write_all(&body)
                }
            });
            if sent.is_err() {
                return;
            }
        }
    })
}

/// Reads one request head and its body. `None` at end of stream or on any error; else
/// whether the request was a HEAD.
fn drain_request(reader: &mut BufReader<TcpStream>) -> Option<bool> {
    let mut line = String::new();
    let mut head_only = None;
    let mut length = 0u64;
    let mut chunked = false;
    loop {
        line.clear();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        if head_only.is_none() {
            head_only = Some(line.starts_with("HEAD "));
            continue;
        }
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok()?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        }
    }
    if chunked {
        loop {
            line.clear();
            reader.read_line(&mut line).ok()?;
            let digits = line.split([';', '\r']).next()?;
            let size = u64::from_str_radix(digits.trim(), 16).ok()?;
            if size == 0 {
                loop {
                    line.clear();
                    if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" {
                        break;
                    }
                }
                break;
            }
            skip(reader, size + 2)?;
        }
    } else {
        skip(reader, length)?;
    }
    head_only
}

fn skip(reader: &mut BufReader<TcpStream>, n: u64) -> Option<()> {
    let copied = std::io::copy(&mut reader.by_ref().take(n), &mut std::io::sink()).ok()?;
    (copied == n).then_some(())
}

/// One case from h2spec's JUnit report.
#[derive(Debug)]
struct Case {
    /// `<spec>/<section>/<n>`, as h2spec takes it on its command line.
    id: String,
    title: String,
    passed: bool,
}

/// The cases of an h2spec JUnit report. Each `<testsuite>` is one section, its `package`
/// attribute the section's id; its `<testcase>`s are numbered from 1 in order. A case that
/// failed or was skipped holds a `<failure>`, `<error>` or `<skipped>` element.
fn cases(report: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    for suite in report.split("<testsuite ").skip(1) {
        let section = attribute(suite, "package").expect("a section id");
        for (n, case) in suite.split("<testcase ").skip(1).enumerate() {
            let element = match case.find("</testcase>") {
                Some(end) => &case[..end],
                None => case.split_once("/>").expect("a closed testcase").0,
            };
            cases.push(Case {
                id: format!("{section}/{}", n + 1),
                title: attribute(case, "classname").unwrap_or_default(),
                passed: !["<failure", "<error", "<skipped"]
                    .iter()
                    .any(|tag| element.contains(tag)),
            });
        }
    }
    cases
}

fn attribute(element: &str, name: &str) -> Option<String> {
    let start = element.find(&format!(" {name}=\""))? + name.len() + 3;
    let len = element[start..].find('"')?;
    Some(element[start..start + len].to_owned())
}

#[test]
fn junit_reports_number_cases_within_their_section() {
    let report = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="5.1. Stream States" package="http2/5.1" id="5.1" tests="2" failures="1">
    <testcase package="http2/5.1" classname="idle: Sends a DATA frame" time="0.0003"></testcase>
    <testcase package="http2/5.1" classname="idle: Sends a RST_STREAM frame" time="1"><failure>timeout</failure></testcase>
  </testsuite>
  <testsuite name="2. Huffman" package="hpack/2" id="2" tests="1" skipped="1">
    <testcase package="hpack/2" classname="Sends a huffman string" time="0"><skipped>x</skipped></testcase>
  </testsuite>
</testsuites>"#;
    let found: Vec<_> = cases(report)
        .into_iter()
        .map(|c| (c.id, c.title, c.passed))
        .collect();
    assert_eq!(
        found,
        [
            (
                "http2/5.1/1".into(),
                "idle: Sends a DATA frame".into(),
                true
            ),
            (
                "http2/5.1/2".into(),
                "idle: Sends a RST_STREAM frame".into(),
                false
            ),
            ("hpack/2/1".into(), "Sends a huffman string".into(), false),
        ]
    );
}

/// Runs every h2spec case against `path` and returns the report's cases.
fn run(h2spec: &str, port: u16, path: &str) -> Vec<Case> {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("h2spec.xml");
    let output = Command::new(h2spec)
        .args(["--strict", "--tls", "--insecure", "--host", "localhost"])
        .args(["--port", &port.to_string(), "--path", path])
        .args(["--timeout", CASE_TIMEOUT_SECS])
        .arg("--junit-report")
        .arg(&report)
        .output()
        .expect("h2spec starts");
    let log = String::from_utf8_lossy(&output.stdout);
    let report = std::fs::read_to_string(&report)
        .unwrap_or_else(|e| panic!("h2spec wrote no report ({e}) for {path}:\n{log}"));
    let cases = cases(&report);
    for spec in ["generic/", "http2/", "hpack/"] {
        assert!(
            cases.iter().any(|c| c.id.starts_with(spec)),
            "h2spec ran no {spec} case for {path}:\n{log}"
        );
    }
    let failed = cases.iter().filter(|c| !c.passed).count();
    assert_eq!(
        output.status.success(),
        failed == 0,
        "h2spec's exit status and report disagree for {path}:\n{log}"
    );
    cases
}

/// The cases whose outcome differs from [`EXCLUDED`]: failures not listed, and listed cases
/// that pass.
fn unexpected(cases: &[Case]) -> Vec<String> {
    let mut found: Vec<_> = cases
        .iter()
        .filter(|c| c.passed == EXCLUDED.iter().any(|(id, _)| *id == c.id))
        .map(|c| {
            let outcome = if c.passed { "passes" } else { "fails" };
            format!("{} {outcome}: {}", c.id, c.title)
        })
        .collect();
    found.extend(
        EXCLUDED
            .iter()
            .filter(|(id, _)| !cases.iter().any(|c| c.id == *id))
            .map(|(id, _)| format!("{id} is listed and h2spec has no such case")),
    );
    found
}

#[test]
fn h2spec_passes_on_a_local_route_and_a_proxied_route() {
    let Some(h2spec) = h2spec() else {
        assert!(
            std::env::var_os("UPSTREAMER_REQUIRE_H2SPEC").is_none(),
            "h2spec is required and not found"
        );
        eprintln!("h2spec not found; skipping the HTTP/2 conformance suite");
        return;
    };
    let origin = origin();
    // h2spec connects to a host name and sends it as the SNI; the proxy refuses a handshake
    // without one.
    let sites = json!([{
        "name": "h2spec",
        "hosts": ["localhost"],
        "tls": {
            "cert": "/nonexistent/fullchain.pem",
            "key": "/nonexistent/key.pem",
            "redirectHttp": false,
            "http3": false,
        },
        "routes": [
            { "name": "proxied", "when": { "path": "/proxied" }, "proxy": origin.url() },
            { "name": "local", "respond": { "body": "l".repeat(BODY_LEN) } },
        ],
    }]);
    let port = Reserved::new();
    let _proxy = Proxy::start_with(
        sites,
        json!({ "listen": { "http": [], "https": [port.addr] } }),
    );

    let mut problems = Vec::new();
    for path in ["/", "/proxied"] {
        let cases = run(&h2spec, port.addr.port(), path);
        problems.extend(
            unexpected(&cases)
                .into_iter()
                .map(|p| format!("{path}: {p}")),
        );
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
