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

fn example(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(format!("{name}.toml"))
        .display()
        .to_string()
}

fn temp_file(name: &str, text: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    let path = path.display().to_string();
    (dir, path)
}

#[test]
fn check_reads_toml_by_extension() {
    let out = upstreamer(&["check", &example("minimal")]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "ok: 1 sites, 1 steps\n"
    );

    let out = upstreamer(&["check", "--config", &example("metrics")]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("ok: 2 sites, ") && stdout.contains(", metrics on ("),
        "{stdout}"
    );
}

#[test]
fn check_rejects_invalid_toml_on_stderr_with_status_1() {
    let (_dir, path) = temp_file(
        "broken.toml",
        "version = 1\n[[sites]]\nname = 'a'\nhosts = ['a.example']\nroutes = [{ proxi = 'x' }]\n",
    );
    let out = upstreamer(&["check", &path]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!(
            "{path}:/sites/0/routes/0: a/0: unknown key `proxi`"
        )),
        "{stderr}"
    );
    assert!(
        stderr.trim_end().ends_with("(line 5, column 11)"),
        "{stderr}"
    );
    assert!(out.stdout.is_empty());

    let (_dir, path) = temp_file("syntax.toml", "version = 1\n[[sites]\n");
    let out = upstreamer(&["check", &path]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("(line 2, column"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_extension_alone_picks_the_format() {
    let toml = std::fs::read_to_string(example("minimal")).unwrap();
    let (_dir, path) = temp_file("config.json", &toml);
    let out = upstreamer(&["check", &path]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "TOML text in a .json file is not JSON"
    );
}

#[test]
fn an_example_is_a_config_that_check_accepts() {
    let out = upstreamer(&["example"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text, std::fs::read_to_string(example("minimal")).unwrap());
    let (_dir, path) = temp_file("upstreamer.toml", &text);
    let out = upstreamer(&["check", "--config", &path]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn every_example_file_is_listed_and_printable() {
    let list = upstreamer(&["example", "--list"]);
    assert_eq!(list.status.code(), Some(0));
    let list = String::from_utf8(list.stdout).unwrap();
    let mut files: Vec<String> =
        std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("examples"))
            .unwrap()
            .filter_map(|e| {
                let path = e.unwrap().path();
                (path.extension()? == "toml")
                    .then(|| path.file_stem().unwrap().to_string_lossy().into_owned())
            })
            .collect();
    files.sort();
    let mut listed: Vec<&str> = list
        .lines()
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    listed.sort_unstable();
    assert_eq!(listed, files);
    for name in files {
        let out = upstreamer(&["example", &name]);
        assert_eq!(out.status.code(), Some(0), "{name}");
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            std::fs::read_to_string(example(&name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn an_unknown_example_is_a_usage_error() {
    let out = upstreamer(&["example", "nginx"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("no example named \"nginx\""), "{stderr}");
    assert!(stderr.contains("minimal"), "{stderr}");
}

#[test]
fn convert_turns_json_into_a_toml_that_means_the_same() {
    let json = fixture("config/custom.json");
    let out = upstreamer(&["convert", &json]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let toml = String::from_utf8(out.stdout).unwrap();
    let (_dir, path) = temp_file("custom.toml", &toml);
    let check = upstreamer(&["check", &path]);
    assert_eq!(
        check.status.code(),
        Some(0),
        "{}\n{toml}",
        String::from_utf8_lossy(&check.stderr)
    );
    // And back: the JSON of that TOML is the original, with `null` as `false` in header maps
    // and left out elsewhere.
    let back = upstreamer(&["convert", &path]);
    assert_eq!(back.status.code(), Some(0));
    let back: serde_json::Value = serde_json::from_slice(&back.stdout).unwrap();
    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(back, spell_without_null(original, ""));
}

/// What TOML can say of `value`: a header removal as `false`, any other `null` as no key.
fn spell_without_null(value: serde_json::Value, key: &str) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter_map(|(k, v)| match v {
                    Value::Null if matches!(key, "headers" | "requestHeaders") => {
                        Some((k, Value::Bool(false)))
                    }
                    Value::Null => None,
                    v => {
                        let v = spell_without_null(v, &k);
                        Some((k, v))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|v| spell_without_null(v, ""))
                .collect(),
        ),
        v => v,
    }
}

#[test]
fn convert_turns_toml_into_json_with_the_names_first() {
    let out = upstreamer(&["convert", &example("minimal")]);
    assert_eq!(out.status.code(), Some(0));
    let json = String::from_utf8(out.stdout).unwrap();
    assert!(json.starts_with("{\n  \"version\": 1,\n"), "{json}");
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["sites"][0]["routes"][0]["proxy"],
        "http://127.0.0.1:3000"
    );
    assert_eq!(value["listen"]["http"][0], "0.0.0.0:8080");
}

#[test]
fn convert_names_the_line_of_a_toml_mistake_and_exits_1() {
    let (_dir, path) = temp_file("bad.toml", "version = 1\nafter = 2026-12-01\n");
    let out = upstreamer(&["convert", &path]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.starts_with(&format!("{path}: ")), "{stderr}");
    assert!(stderr.contains("no time zone"), "{stderr}");
    assert!(
        stderr.trim_end().ends_with("(line 2, column 9)"),
        "{stderr}"
    );

    let (_dir, path) = temp_file("bad.json", "{\"version\": ");
    let out = upstreamer(&["convert", &path]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn convert_cannot_write_a_null_inside_an_array() {
    let (_dir, path) = temp_file("null.json", r#"{"version":1,"x":[1,null]}"#);
    let out = upstreamer(&["convert", &path]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("/x/1: TOML has no null"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn convert_and_example_usage_errors_exit_2() {
    for args in [
        &["convert"][..],
        &["convert", "a", "b"],
        &["convert", "--to", "yaml", "a"],
        &["example", "a", "b"],
        &["example", "--bogus"],
    ] {
        let out = upstreamer(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage:"),
            "{args:?}"
        );
    }
    let out = upstreamer(&["convert", "/nonexistent/config.toml"]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn reload_usage_errors_exit_2() {
    for args in [
        &["reload"][..],
        &["reload", "--reload-socket"],
        &["reload", "/run/upstreamer/reload"],
        &["reload", "--reload-socket", "a", "--reload-socket", "b"],
        &["run", "config.json", "--reload-socket"],
    ] {
        let out = upstreamer(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage:"),
            "{args:?}"
        );
    }
}

/// Runs `upstreamer reload` against a server that greets its one client with `greeting` and
/// then closes the connection. `main_pid` is the variable systemd sets for a reload command.
fn reload_greeted_with(greeting: &'static str, main_pid: Option<&str>) -> Output {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("reload");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(greeting.as_bytes()).unwrap();
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_upstreamer"));
    command.args(["reload", "--reload-socket"]).arg(&socket);
    match main_pid {
        Some(pid) => command.env("MAINPID", pid),
        None => command.env_remove("MAINPID"),
    };
    let out = command.output().unwrap();
    server.join().unwrap();
    out
}

#[test]
fn reload_leaves_a_process_it_cannot_ask_to_the_service_manager_s_signal() {
    let newer = "{\"versions\":[2,3]}\n";
    let out = reload_greeted_with(newer, Some("4242"));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        stderr,
        "upstreamer: the running process speaks reload protocol version 2, 3, this program 1; \
         leaving the reload to the service manager's signal, after which only the service's \
         status says whether it failed\n"
    );

    let out = reload_greeted_with(newer, None);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "nothing signals the process: {stderr}"
    );
    assert_eq!(
        stderr,
        "upstreamer: the running process speaks reload protocol version 2, 3, this program 1; \
         send it SIGHUP to reload it\n"
    );
}

#[test]
fn reload_fails_when_the_running_process_goes_without_an_answer() {
    for main_pid in [None, Some("4242")] {
        let out = reload_greeted_with("{\"versions\":[1]}\n", main_pid);
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(3), "{stderr}");
        assert!(
            stderr.contains("closed the connection before it answered"),
            "{stderr}"
        );
    }
}
