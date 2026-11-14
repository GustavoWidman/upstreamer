//! `upstreamer::check` on the configs the NixOS module emits for the example hosts
//! (`tests/fixtures/config`, kept equal to the module's output by the flake's `module-eval`
//! check) and on generated route fragments (`tests/fixtures/site/upstreamer`, whose `@out@`
//! stands for the site package's store path). Then one config per diagnostic the compiler
//! reports, each located by its JSON pointer.

use std::path::{Path, PathBuf};

use upstreamer::{CheckInput, ExpectedPorts, check};

fn fixtures(dir: &str) -> Vec<PathBuf> {
    let dir = fixture_dir(dir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no fixtures in {}", dir.display());
    files
}

fn fixture_dir(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
}

fn messages(diagnostics: &[upstreamer::Diagnostic]) -> Vec<String> {
    diagnostics.iter().map(ToString::to_string).collect()
}

/// The emitted configs include the site fragments by their store path. The copy of that
/// store path in the fixtures stands in for it, so the check does not depend on the store.
fn with_local_includes(path: &Path) -> PathBuf {
    let text = std::fs::read_to_string(path).unwrap();
    let store = store_prefix(&text);
    let text = match store {
        Some(prefix) => text.replace(
            &prefix,
            &fixture_dir("site/upstreamer").display().to_string(),
        ),
        None => text,
    };
    let out = tempfile::tempdir()
        .unwrap()
        .keep()
        .join(path.file_name().unwrap());
    std::fs::write(&out, text).unwrap();
    out
}

/// `/nix/store/<hash>-example-site-fragments`, if the config includes from it.
fn store_prefix(text: &str) -> Option<String> {
    let start = text.find("/nix/store/")?;
    let end =
        start + text[start..].find("-example-site-fragments")? + "-example-site-fragments".len();
    Some(text[start..end].to_owned())
}

#[test]
fn emitted_configs_pass() {
    for path in fixtures("config") {
        let report = check(CheckInput::Config {
            path: with_local_includes(&path),
            expect: None,
        })
        .unwrap_or_else(|d| panic!("{}: {:#?}", path.display(), messages(&d)));
        assert!(report.sites > 0, "{} has sites", path.display());
    }
}

#[test]
fn routing_fixtures_pass() {
    let dir = fixture_dir("routing");
    for name in ["portfolio/main.json", "portfolio/blog.json"] {
        let report = check(CheckInput::Fragment(dir.join(name)))
            .unwrap_or_else(|d| panic!("{name}: {:#?}", messages(&d)));
        assert!(report.steps > 30, "{name} has its steps");
    }
    let heimdall = check(CheckInput::Config {
        path: dir.join("heimdall/config.json"),
        expect: Some(ExpectedPorts {
            tcp: vec![80, 443],
            udp: vec![443],
        }),
    })
    .unwrap_or_else(|d| panic!("heimdall: {:#?}", messages(&d)));
    assert_eq!(heimdall.sites, 1);
}

#[test]
fn generated_fragments_pass() {
    for path in fixtures("site/upstreamer") {
        let report = check(CheckInput::Fragment(path.clone()))
            .unwrap_or_else(|d| panic!("{}: {:#?}", path.display(), messages(&d)));
        assert!(report.steps > 10, "{} has its steps", path.display());
    }
}

fn check_json(json: &str) -> (PathBuf, Vec<String>) {
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("config.json");
    std::fs::write(&path, json).unwrap();
    let errors = check(CheckInput::Config {
        path: path.clone(),
        expect: None,
    })
    .expect_err("an invalid config");
    (path, messages(&errors))
}

#[test]
fn a_schema_error_names_its_pointer_site_and_step() {
    let (path, errors) = check_json(
        r#"{"version":1,"sites":[
            {"name":"a","hosts":["a.example"],"routes":[]},
            {"name":"b","hosts":["b.example"],"routes":[
                {"name":"rewrites","firstOf":[{"rewrite":"/x"},{"name":"api","proxy":5}]}
            ]}
        ]}"#,
    );
    let prefix = format!(
        "{}:/sites/1/routes/0/firstOf/1/proxy: b/rewrites/api: invalid type: integer `5`",
        path.display()
    );
    assert_eq!(errors.len(), 1);
    assert!(errors[0].starts_with(&prefix), "{}", errors[0]);
}

#[test]
fn a_step_with_two_actions_is_rejected() {
    let (path, errors) = check_json(
        r#"{"version":1,"sites":[{"name":"a","hosts":["a.example"],"routes":[{"proxy":"http://127.0.0.1:1","error":404}]}]}"#,
    );
    let prefix = format!(
        "{}:/sites/0/routes/0: a/0: a step has exactly one action, found `proxy` and `error`",
        path.display()
    );
    assert!(errors[0].starts_with(&prefix), "{}", errors[0]);
}

#[test]
fn an_unknown_site_key_is_rejected() {
    let (_, errors) =
        check_json(r#"{"version":1,"sites":[{"name":"a","hosts":["a.example"],"tsl":null}]}"#);
    assert!(
        errors[0].contains(":/sites/0/tsl: a: unknown field `tsl`"),
        "{}",
        errors[0]
    );
}

#[test]
fn another_config_version_is_rejected() {
    let (path, errors) = check_json(r#"{"version":2,"sites":[]}"#);
    assert_eq!(
        errors,
        [format!(
            "{}:/version: unsupported config version 2; this upstreamer reads version 1",
            path.display()
        )]
    );
}

#[test]
fn a_missing_file_is_a_diagnostic() {
    let errors = check(CheckInput::Fragment("/nonexistent/fragment.json".into())).unwrap_err();
    assert!(
        messages(&errors)[0].starts_with("/nonexistent/fragment.json: cannot read: "),
        "{:?}",
        messages(&errors)
    );
}

fn check_json_with(
    json: &str,
    files: &[(&str, &str)],
    expect: Option<ExpectedPorts>,
) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("config.json");
    for (name, text) in files {
        std::fs::write(
            dir.join(name),
            text.replace("@dir@", &dir.display().to_string()),
        )
        .unwrap();
    }
    std::fs::write(&path, json.replace("@dir@", &dir.display().to_string())).unwrap();
    let errors = check(CheckInput::Config { path, expect }).expect_err("an invalid config");
    messages(&errors)
        .into_iter()
        .map(|m| m.replace(&dir.display().to_string(), "@dir@"))
        .collect()
}

fn site(routes: &str) -> String {
    format!(r#"{{"version":1,"sites":[{{"name":"a","hosts":["a.example"],"routes":{routes}}}]}}"#)
}

#[test]
fn an_unknown_placeholder_is_rejected() {
    let errors = check_json_with(
        &site(
            r#"[{"set":{"lang":"en"}},{"name":"tree","set":{"tree":"/srv/{vars.lang}/{lang}"}}]"#,
        ),
        &[],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json:/sites/0/routes/1/set/tree: a/tree: unknown placeholder `{lang}` (at byte 17 of \"/srv/{vars.lang}/{lang}\")"
        ]
    );
}

#[test]
fn a_capture_group_the_regex_does_not_have_is_rejected() {
    let errors = check_json_with(
        &site(
            r#"[{"name":"old","when":{"pathRegex":"^/old/(.*)$"},"redirect":{"to":"/{re.2}","status":301}}]"#,
        ),
        &[],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json:/sites/0/routes/0/redirect/to: a/old: `{re.2}`: the regex in this step's `when` has 1 capture group (at byte 1 of \"/{re.2}\")"
        ]
    );
}

#[test]
fn a_capture_without_a_regex_in_its_own_step_is_rejected() {
    let errors = check_json_with(
        &site(r#"[{"when":{"pathRegex":"^/(a)$"},"routes":[{"rewrite":"/{re.1}"}]}]"#),
        &[],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json:/sites/0/routes/0/routes/0/rewrite: a/0/0: `{re.1}` needs a `pathRegex` or `regex` in this step's own `when` (at byte 1 of \"/{re.1}\")"
        ]
    );
}

#[test]
fn a_framing_header_op_is_rejected() {
    let errors = check_json_with(
        &site(
            r#"[{"name":"len","headers":{"Content-Length":"0"}},{"requestHeaders":{"Transfer-Encoding":null}}]"#,
        ),
        &[],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json:/sites/0/routes/0/headers/Content-Length: a/len: `Content-Length` is a framing or hop-by-hop header, which only the protocol layer writes",
            "@dir@/config.json:/sites/0/routes/1/requestHeaders/Transfer-Encoding: a/1: `Transfer-Encoding` is a framing or hop-by-hop header, which only the protocol layer writes",
        ]
    );
}

#[test]
fn a_duplicate_host_on_a_listener_is_rejected() {
    let errors = check_json_with(
        r#"{"version":1,"sites":[
            {"name":"a","hosts":["a.example"],"tls":{"cert":"/c","key":"/k"},"routes":[]},
            {"name":"b","hosts":["b.example","A.example"],"tls":{"cert":"/c","key":"/k"},"routes":[]},
            {"name":"plain","hosts":["b.example"],"routes":[]}
        ]}"#,
        &[],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json:/sites/1/hosts/1: b: host `a.example` on https 0.0.0.0:443 is served by both site `a` and site `b`",
            "@dir@/config.json:/sites/1/hosts/0: b: host `b.example` on http 0.0.0.0:80 is served by both site `plain` and the HTTP->HTTPS redirect of site `b`",
        ]
    );
}

#[test]
fn an_include_cycle_is_rejected() {
    let errors = check_json_with(
        &site(r#"[{"include":"@dir@/one.json"}]"#),
        &[
            (
                "one.json",
                r#"{"fragment":1,"routes":[{"name":"two","include":"@dir@/two.json"}]}"#,
            ),
            (
                "two.json",
                r#"{"fragment":1,"routes":[{"name":"back","include":"@dir@/one.json"}]}"#,
            ),
        ],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/two.json:/routes/0/include: a/back: include cycle: @dir@/one.json -> @dir@/two.json -> @dir@/one.json"
        ]
    );
}

#[test]
fn a_firewall_that_disagrees_with_the_listeners_is_rejected() {
    let config = r#"{"version":1,"sites":[
        {"name":"a","hosts":["a.example"],"tls":{"cert":"/c","key":"/k"},"routes":[]},
        {"name":"lab","hosts":["*"],"listen":["0.0.0.0:8080"],"routes":[]}
    ]}"#;
    let errors = check_json_with(
        config,
        &[],
        Some(ExpectedPorts {
            tcp: vec![443, 80],
            udp: vec![],
        }),
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json: the firewall opens TCP 80, 443 and UDP none, but the sites listen on TCP 80, 443, 8080 and UDP 443"
        ]
    );
}

#[test]
fn conflicting_idle_timeouts_on_one_origin_are_rejected() {
    let errors = check_json_with(
        &site(
            r#"[
            {"when":{"path":"/a/*"},"proxy":{"to":"http://127.0.0.1:9000","timeouts":{"idle":"30s"}}},
            {"name":"rest","proxy":"http://127.0.0.1:9000"}
        ]"#,
        ),
        &[],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json:/sites/0/routes/1/proxy/timeouts/idle: a/rest: origin http://127.0.0.1:9000 already has idle timeout 30s from another proxy step, not 2m; one origin has one idle timeout"
        ]
    );
}

#[test]
fn every_problem_of_a_config_is_reported_at_once() {
    let errors = check_json_with(
        &site(
            r#"[{"redirect":{"to":"/","status":200}},{"error":200},{"respond":{"status":42}},{"rewrite":"x"}]"#,
        ),
        &[],
        None,
    );
    assert_eq!(
        errors,
        [
            "@dir@/config.json:/sites/0/routes/0/redirect/status: a/0: 200 is not a redirect status (301, 302, 303, 307, 308)",
            "@dir@/config.json:/sites/0/routes/1/error: a/1: 200 is not an error status (400 to 599)",
            "@dir@/config.json:/sites/0/routes/2/respond/status: a/2: 42 is not a response status (200 to 599)",
            "@dir@/config.json:/sites/0/routes/3/rewrite: a/3: a rewrite target is a path starting with `/`",
        ]
    );
}

#[test]
fn warnings_do_not_fail_a_check() {
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        site(r#"[{"name":"all","proxy":"http://127.0.0.1:1"},{"name":"late","rewrite":"/{vars.never}"}]"#),
    )
    .unwrap();
    let report = check(CheckInput::Config { path, expect: None }).expect("warnings only");
    let warnings = messages(&report.warnings);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].starts_with("warning: "), "{warnings:?}");
    assert!(
        warnings[0].contains("/sites/0/routes/1: a/late: unreachable"),
        "{warnings:?}"
    );
    assert!(
        warnings[1].contains("`{vars.never}` is read before any `set` assigns it"),
        "{warnings:?}"
    );
}
