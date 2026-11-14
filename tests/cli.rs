//! The `upstreamer` command line: exit codes and where its output goes.

use std::path::Path;
use std::process::{Command, Output};

fn upstreamer(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_upstreamer"))
        .args(args)
        .output()
        .unwrap()
}

fn fixture(rel: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
        .display()
        .to_string()
}

#[test]
fn check_accepts_a_valid_config() {
    let config = fixture("config/edge.json");
    for args in [
        vec!["check", config.as_str()],
        vec![
            "check",
            "--config",
            &config,
            "--expect-tcp",
            "80,443",
            "--expect-udp",
            "443",
        ],
    ] {
        let out = upstreamer(&args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(stdout.starts_with("ok: 3 sites, "), "{stdout}");
    }
}

#[test]
fn check_rejects_a_firewall_that_disagrees_with_the_listeners() {
    let config = fixture("config/edge.json");
    let out = upstreamer(&[
        "check",
        &config,
        "--expect-tcp",
        "80,443",
        "--expect-udp",
        "",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        stderr.trim_end(),
        format!(
            "{config}: the firewall opens TCP 80, 443 and UDP none, but the sites listen on TCP 80, 443 and UDP 443"
        )
    );
}

#[test]
fn check_accepts_a_fragment() {
    let out = upstreamer(&["check", "--fragment", &fixture("site/upstreamer/main.json")]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_reports_an_invalid_config_on_stderr_with_status_1() {
    let out = upstreamer(&["check", "--fragment", &fixture("config/edge.json")]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("edge.json:/http3: unknown field `http3`"),
        "{stderr}"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &[][..],
        &["serve"],
        &["check"],
        &["check", "--bogus", "x"],
        &["run", "--workers", "0", "x"],
        &["check", "a", "b"],
    ] {
        let out = upstreamer(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage:"),
            "{args:?}"
        );
    }
}

#[test]
fn help_exits_0() {
    let out = upstreamer(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("usage:"));
}
