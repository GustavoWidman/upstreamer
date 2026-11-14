//! Differential tests: each fleet host served by Caddy from the Caddyfile it runs today and by
//! upstreamer from the config the NixOS module emits for it, both over plain HTTP on loopback,
//! with the same fixture origins and static trees. Every probe of `differential/corpus/` goes
//! to both, and the normalised answers (status, headers, body, what each origin read) must be
//! equal, or differ exactly as `differential/known.json` records.
//!
//! A difference that `known.json` does not record fails the test, and so does a recorded one
//! that no longer happens. The failure writes the unrecorded differences, in `known.json`'s
//! shape, to `differential-<host>.json` in Cargo's test temporary directory.
//!
//! The tests skip when no `caddy` is on PATH (`nix shell nixpkgs#caddy`).

mod support;

#[path = "differential/compare.rs"]
mod compare;
#[path = "differential/harness.rs"]
mod harness;
#[path = "differential/origin.rs"]
mod origin;

use compare::{Difference, Kind};
use harness::{Host, Side};
use serde_json::Value;
use std::collections::BTreeSet;

/// Runs every probe of `host` against both servers; returns every difference. Both sides'
/// observations go to `differential-<name>-observed.txt` in Cargo's test temporary directory.
fn run(name: &str, host: &Host, edit: &(dyn Fn(&mut Value) + Sync)) -> Vec<Difference> {
    let (caddy, ours) = std::thread::scope(|scope| {
        let caddy = scope.spawn(|| harness::observe(host, Side::Caddy, &|_| {}));
        let ours = scope.spawn(|| harness::observe(host, Side::Upstreamer, edit));
        (caddy.join().unwrap(), ours.join().unwrap())
    });
    let probes = host
        .sites
        .iter()
        .flat_map(|site| site.probes.iter().map(move |p| (&site.host, &p.name)));
    let mut differences = Vec::new();
    let mut dump = String::new();
    for ((site, probe), (c, u)) in probes.zip(caddy.iter().zip(&ours)) {
        differences.extend(compare::differences(site, probe, c, u));
        dump.push_str(&format!(
            "## {site} {probe:?}\ncaddy {}upstreamer {}\n",
            c.show(),
            u.show()
        ));
    }
    std::fs::write(
        temporary(&format!("differential-{name}-observed.txt")),
        dump,
    )
    .unwrap();
    differences
}

fn temporary(file: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(file)
}

fn check(name: &str) {
    if !harness::caddy_available() {
        eprintln!("skipped: caddy is not on PATH");
        return;
    }
    let host = harness::load(name);
    for site in &host.sites {
        let mut seen = BTreeSet::new();
        for probe in &site.probes {
            assert!(
                seen.insert(&probe.name),
                "{}: two probes named {:?}",
                site.host,
                probe.name
            );
        }
    }
    let differences = run(name, &host, &|_| {});

    let sites: BTreeSet<&str> = host.sites.iter().map(|s| s.host.as_str()).collect();
    let known = compare::known();
    let mut recorded = Vec::new();
    for group in &known {
        for difference in &group.differences {
            if sites.contains(difference.site.as_str()) {
                recorded.push((group, difference));
            }
        }
    }
    for (group, difference) in &recorded {
        if differences.contains(difference) {
            let kind = if group.kind == Kind::Finding {
                "finding"
            } else {
                "accepted"
            };
            eprintln!(
                "{kind}: {} {:?} {}\n  caddy:      {}\n  upstreamer: {}\n  ({})",
                difference.site,
                difference.probe,
                difference.field,
                difference.caddy,
                difference.upstreamer,
                group.about
            );
        }
    }
    let unrecorded: Vec<&Difference> = differences
        .iter()
        .filter(|d| !recorded.iter().any(|(_, r)| r == d))
        .collect();
    let stale: Vec<&Difference> = recorded
        .iter()
        .map(|(_, r)| *r)
        .filter(|r| !differences.contains(r))
        .collect();
    if unrecorded.is_empty() && stale.is_empty() {
        return;
    }
    let out = temporary(&format!("differential-{name}.json"));
    std::fs::write(&out, serde_json::to_string_pretty(&unrecorded).unwrap()).unwrap();
    let show = |ds: &[&Difference]| {
        ds.iter()
            .map(|d| {
                format!(
                    "  {} {:?} {}\n    caddy:      {}\n    upstreamer: {}",
                    d.site, d.probe, d.field, d.caddy, d.upstreamer
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    panic!(
        "{name}: {} unrecorded differences (written to {}):\n{}\n{} recorded differences no longer happen:\n{}",
        unrecorded.len(),
        out.display(),
        show(&unrecorded),
        stale.len(),
        show(&stale)
    );
}

/// heimdall, the binary cache and its S3 endpoint.
#[test]
fn edge() {
    check("edge");
}

/// The portfolio's main and blog hosts, DNS-over-HTTPS, the DERP relay, the game panel, the
/// file share, webmail and the tailnet admin.
#[test]
fn apps() {
    check("apps");
}

/// The desktop host's noVNC catch-all.
#[test]
fn desktop() {
    check("desktop");
}

/// The comparison notices a broken route: with heimdall's API route moved off `/api/*` in a
/// copy of the emitted config, the API probes differ in ways `known.json` does not record.
#[test]
fn a_broken_route_differs() {
    if !harness::caddy_available() {
        eprintln!("skipped: caddy is not on PATH");
        return;
    }
    let mut host = harness::load("edge");
    host.sites.retain(|site| site.host == "app.example.com");
    let break_api = |doc: &mut Value| {
        let sites = doc["sites"].as_array_mut().unwrap();
        let app = sites
            .iter_mut()
            .find(|s| s["name"] == "app.example.com")
            .unwrap();
        let routes = app["routes"].as_array_mut().unwrap();
        let api = routes.iter_mut().find(|r| r["name"] == "api").unwrap();
        api["when"]["path"] = Value::from("/apis/*");
    };
    let differences = run("broken-route", &host, &break_api);
    let known = compare::known();
    let unrecorded: Vec<&Difference> = differences
        .iter()
        .filter(|d| !known.iter().any(|g| g.differences.contains(d)))
        .collect();
    assert!(
        unrecorded
            .iter()
            .any(|d| d.probe == "api GET with a query" && d.field == "upstream"),
        "the broken API route went unnoticed: {unrecorded:#?}"
    );
}
