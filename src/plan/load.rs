//! Reading a config into a plan, for `run` and for `check`: the format dispatch, the version
//! check, locating diagnostics in the document they point into, and what `check` reports.

use super::{Action, Block, Diagnostic, ListenerKind, Plan, compile};
use crate::config::{self, Document, Format, Parsed};
use std::path::{Path, PathBuf};

/// What `check` reports beside sites and steps: what each feature costs at run time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Costs {
    /// Balanced targets.
    pub pools: usize,
    /// Origins the config names.
    pub origins: usize,
    /// Origins with an active health check.
    pub probed: usize,
    /// `limit` steps, and the memory of their bucket tables.
    pub limits: usize,
    pub limit_bytes: usize,
    /// Metric series; `None` when no site has a `metrics` step.
    pub series: Option<usize>,
    /// Discovery sources.
    pub sources: usize,
}

/// Reads, parses and compiles a config file: what `run` does at startup and reload, and what
/// `check` does at build time. JSON or TOML by the file's extension. Every diagnostic names
/// its file and is located (site and step); for TOML it ends with the value's
/// `(line L, column C)`, the suffix JSON syntax errors already carry.
pub(crate) fn load(
    path: &Path,
    generation: u64,
) -> Result<(Plan, Vec<Diagnostic>), Vec<Diagnostic>> {
    let bytes = std::fs::read(path).map_err(|e| {
        vec![Diagnostic::error(
            Some(path),
            "",
            format!("cannot read: {e}"),
        )]
    })?;
    let format = Format::of(path);
    let Parsed { value: config, doc } = config::parse_config(format, &bytes).map_err(|e| {
        let d = schema_diagnostic(path, e);
        vec![match config::document(format, &bytes) {
            Some(doc) => d.locate(&doc),
            None => d,
        }]
    })?;
    let in_config = |diagnostics: Vec<Diagnostic>| -> Vec<Diagnostic> {
        diagnostics
            .into_iter()
            .map(|mut d| {
                if d.file.is_none() {
                    d.file = Some(path.to_path_buf());
                }
                if d.file.as_deref() == Some(path) {
                    d.locate(&doc)
                } else {
                    d
                }
            })
            .collect()
    };
    if config.version != 1 {
        let message = format!(
            "unsupported config version {}; this upstreamer reads version 1",
            config.version
        );
        return Err(in_config(vec![Diagnostic::error(
            Some(path),
            "/version",
            message,
        )]));
    }
    match compile::compile(&config, &compile::FileSystem, generation) {
        Ok((plan, warnings)) => Ok((plan, in_config(warnings))),
        Err(diagnostics) => Err(in_config(diagnostics)),
    }
}

/// A document that does not fit the schema, as a diagnostic of `file`.
pub(crate) fn schema_diagnostic(file: &Path, e: config::SchemaError) -> Diagnostic {
    let mut message = e.message;
    if e.line > 0 {
        message.push_str(&format!(" (line {}, column {})", e.line, e.column));
    }
    Diagnostic::error(Some(file), e.pointer, message)
}

/// `upstreamer check`: parse + compile, never touching certificates, roots or sockets.
///
/// A config is compiled exactly as `run` compiles it (includes read and validated), and the
/// ports its listeners need are compared with the ports the NixOS module opens. A fragment is
/// compiled as if one site included it.
pub(crate) fn check(input: crate::CheckInput) -> Result<crate::CheckReport, Vec<Diagnostic>> {
    let (path, expect, fragment) = match input {
        crate::CheckInput::Config { path, expect } => (path, expect, false),
        crate::CheckInput::Fragment(path) => (path, None, true),
    };
    let (plan, warnings) = if fragment {
        let bytes = std::fs::read(&path).map_err(|e| {
            vec![Diagnostic::error(
                Some(&path),
                "",
                format!("cannot read: {e}"),
            )]
        })?;
        let path = std::path::absolute(&path).unwrap_or_else(|_| path.clone());
        let config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "version": 1,
            "sites": [{ "name": "", "hosts": ["*"], "routes": [{ "include": path }] }],
        }))
        .expect("the wrapper fits the schema");
        compile::compile(&config, &OneFile { path, bytes }, 0)?
    } else {
        load(&path, 0)?
    };
    if let Some(expect) = expect {
        ports_match(&plan, &expect)
            .map_err(|message| vec![Diagnostic::error(Some(&path), "", message)])?;
    }
    let sites = &plan.sites[..plan.user_sites as usize];
    let costs = Costs {
        pools: plan.pools.len(),
        origins: plan.origins.len(),
        probed: plan.origins.iter().filter(|o| o.probe.is_some()).count(),
        limits: plan.limits.len(),
        limit_bytes: plan.limits.iter().map(|l| l.slots as usize * 8).sum(),
        series: plan.metrics.then(|| crate::metrics::series(&plan)),
        sources: plan.sources.len(),
    };
    Ok(crate::CheckReport {
        sites: if fragment { 0 } else { sites.len() },
        steps: sites
            .iter()
            .map(|s| {
                count_steps(&s.routes)
                    + s.errors
                        .iter()
                        .map(|e| count_steps(&e.routes))
                        .sum::<usize>()
            })
            .sum(),
        warnings,
        costs,
    })
}

/// One file already read; any other include comes from the file system.
struct OneFile {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl compile::Sources for OneFile {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        if path == self.path {
            Ok(self.bytes.clone())
        } else {
            std::fs::read(path)
        }
    }
}

/// The firewall the NixOS module derived must open exactly the ports the listeners use.
fn ports_match(plan: &Plan, expect: &crate::ExpectedPorts) -> Result<(), String> {
    let set = |ports: &mut dyn Iterator<Item = u16>| -> Vec<u16> {
        let mut v: Vec<u16> = ports.collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let ports = |udp: bool| {
        set(&mut plan
            .listeners
            .iter()
            .filter(|l| (l.key.kind == ListenerKind::Quic) == udp)
            .map(|l| l.key.addr.port()))
    };
    let (tcp, udp) = (ports(false), ports(true));
    let (want_tcp, want_udp) = (
        set(&mut expect.tcp.iter().copied()),
        set(&mut expect.udp.iter().copied()),
    );
    if tcp == want_tcp && udp == want_udp {
        return Ok(());
    }
    let list = |v: &[u16]| match v {
        [] => "none".to_owned(),
        v => v.iter().map(u16::to_string).collect::<Vec<_>>().join(", "),
    };
    Err(format!(
        "the firewall opens TCP {} and UDP {}, but the sites listen on TCP {} and UDP {}",
        list(&want_tcp),
        list(&want_udp),
        list(&tcp),
        list(&udp),
    ))
}

fn count_steps(block: &Block) -> usize {
    block
        .steps
        .iter()
        .map(|step| {
            1 + match &step.action {
                Action::Block(nested) => count_steps(nested),
                _ => 0,
            }
        })
        .sum()
}

impl Diagnostic {
    /// Fills `site` and `step` from the document the pointer points into, so a message about
    /// `/sites/3/routes/1/when` names the site and step a person wrote. For a TOML document,
    /// appends the line and column of the value the pointer names.
    pub(crate) fn locate(mut self, doc: &Document) -> Diagnostic {
        let (site, step) = locate(&doc.value, &self.pointer);
        self.site = site.or(self.site);
        self.step = step;
        let position = doc
            .positions
            .as_ref()
            .and_then(|p| p.position(&self.pointer));
        if let Some((line, column)) = position {
            self.message
                .push_str(&format!(" (line {line}, column {column})"));
        }
        self
    }
}

fn locate(doc: &serde_json::Value, pointer: &str) -> (Option<String>, Option<String>) {
    use serde_json::Value;
    let mut site = None;
    let mut steps: Vec<String> = Vec::new();
    let mut node = doc;
    let mut prev: Option<String> = None;
    for (depth, raw) in pointer.split('/').skip(1).enumerate() {
        let segment = raw.replace("~1", "/").replace("~0", "~");
        let next = match node {
            Value::Object(map) => map.get(&segment),
            Value::Array(items) => segment.parse::<usize>().ok().and_then(|i| items.get(i)),
            _ => None,
        };
        let Some(next) = next else { break };
        if let Value::Array(_) = node {
            let index = &segment;
            match prev.as_deref() {
                Some("sites") if depth == 1 => {
                    site = Some(match next.get("name").and_then(Value::as_str) {
                        Some(name) => name.to_owned(),
                        None => format!("sites[{index}]"),
                    });
                }
                Some("routes" | "firstOf") => {
                    steps.push(match next.get("name").and_then(Value::as_str) {
                        Some(name) => name.to_owned(),
                        None => index.clone(),
                    })
                }
                Some("errors") => steps.push(format!("errors[{index}]")),
                _ => {}
            }
        }
        prev = Some(segment);
        node = next;
    }
    (site, (!steps.is_empty()).then(|| steps.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_file(name: &str, text: &str) -> Result<crate::CheckReport, Vec<String>> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        check(crate::CheckInput::Config { path, expect: None })
            .map_err(|ds| ds.iter().map(|d| d.message.clone()).collect())
    }

    #[test]
    fn check_reports_what_the_features_cost() {
        let report = check_file(
            "config.json",
            r#"{"version":1,"sites":[
                {"name":"a","hosts":["*"],"listen":["127.0.0.1:8080"],
                 "routes":[{"when":{"path":"/metrics"},"metrics":{}},
                           {"when":{"path":"/a"},"proxy":"http://127.0.0.1:9000"},
                           {"proxy":"http://127.0.0.1:9001"}]}]}"#,
        )
        .unwrap();
        assert_eq!(report.costs.origins, 2);
        assert_eq!(
            (
                report.costs.pools,
                report.costs.limits,
                report.costs.sources
            ),
            (0, 0, 0)
        );
        assert!(
            report.costs.series.is_some(),
            "a metrics step counts series"
        );
        let report = check_file(
            "config.json",
            r#"{"version":1,"sites":[{"name":"a","hosts":["*"],"routes":[{"error":404}]}]}"#,
        )
        .unwrap();
        assert_eq!(report.costs, Costs::default(), "no metrics step, no series");
    }

    #[test]
    fn a_toml_file_is_read_as_toml() {
        let errors = check_file("config.toml", "version = 1\n[[sites]\n").unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("(line 2, column"), "{errors:?}");
    }
}
