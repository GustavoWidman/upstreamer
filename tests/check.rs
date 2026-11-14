//! `upstreamer::check` on the configs the NixOS module emits for the example hosts
//! (`tests/fixtures/config`, kept equal to the module's output by the flake's `module-eval`
//! check) and on generated route fragments (`tests/fixtures/site/upstreamer`, whose `@out@`
//! stands for the site package's store path).

use std::path::{Path, PathBuf};

use upstreamer::{CheckInput, check};

fn fixtures(dir: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no fixtures in {}", dir.display());
    files
}

fn messages(diagnostics: &[upstreamer::Diagnostic]) -> Vec<String> {
    diagnostics.iter().map(ToString::to_string).collect()
}

#[test]
fn emitted_configs_pass() {
    for path in fixtures("config") {
        let report = check(CheckInput::Config {
            path: path.clone(),
            expect: None,
        })
        .unwrap_or_else(|d| panic!("{}: {:#?}", path.display(), messages(&d)));
        assert!(report.sites > 0, "{} has sites", path.display());
    }
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
