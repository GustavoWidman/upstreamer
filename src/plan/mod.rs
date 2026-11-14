//! The compiled runtime plan: what the hot path executes. Built once per (re)load by
//! [`compile::compile`] on the control thread, shared read-only by every core through an `Arc`.
//!
//! Everything the config names by string is an index here: vars ([`VarId`]), regexes
//! ([`RegexId`]), upstream origins ([`UpstreamId`]), sites ([`SiteId`]). `include`s are
//! spliced, constant matchers folded, templates parsed into typed placeholders. So routing
//! never hashes a var name, never parses a template, and never sees a config type.

pub(crate) mod compile;
pub(crate) mod cond;
pub(crate) mod host;
pub(crate) mod template;

pub(crate) use cond::Cond;
pub(crate) use host::HostIndex;
pub(crate) use template::Template;

use crate::encode::{Encoding, EncodingSet};
use crate::msg::{HeaderName, Status};
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SiteId(pub u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct VarId(pub u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RegexId(pub u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamId(pub u16);

#[derive(Debug)]
pub(crate) struct Plan {
    /// Monotonic per process; cores compare it to drop per-generation caches.
    pub generation: u64,
    pub workers: Option<u16>,
    pub listeners: Box<[ListenerSpec]>,
    pub sites: Box<[SitePlan]>,
    pub upstreams: Box<[UpstreamPlan]>,
    /// Shared, immutable compiled regexes. Each core keeps its own search caches
    /// (`runtime::RegexCaches`), so matching never contends.
    pub regexes: Box<[regex_automata::meta::Regex]>,
    pub var_count: u16,
    /// Certificate files to load, one per TLS site (sites sharing files share an entry).
    pub certs: Box<[CertSource]>,
    pub server: ServerParams,
}

#[derive(Debug, Clone)]
pub(crate) struct ServerParams {
    pub header_timeout: Duration,
    pub keep_alive: Duration,
    pub h2_idle: Duration,
    pub shutdown: Duration,
    pub max_head_bytes: u32,
    pub max_header_fields: u16,
    pub h2_max_streams: u32,
}

impl Default for ServerParams {
    /// The values a config gets for every `timeouts`/`limits` key it leaves out.
    fn default() -> Self {
        ServerParams {
            header_timeout: Duration::from_secs(10),
            keep_alive: Duration::from_secs(75),
            h2_idle: Duration::from_secs(300),
            shutdown: Duration::from_secs(10),
            max_head_bytes: 32 * 1024,
            max_header_fields: 100,
            h2_max_streams: 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ListenerKind {
    /// Cleartext TCP: plain sites and the HTTP->HTTPS redirect sites.
    Http,
    /// TLS over TCP, ALPN h2 and http/1.1.
    Https,
    /// QUIC on UDP, ALPN h3.
    Quic,
}

/// One bound address. Derived from the sites by the compiler (never written by hand), so the
/// set of sockets and the set of sites cannot disagree.
#[derive(Debug)]
pub(crate) struct ListenerSpec {
    pub key: ListenerKey,
    pub hosts: HostIndex,
}

/// Identity of a listening socket: the address as bound (often a wildcard) and its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ListenerKey {
    pub addr: SocketAddr,
    pub kind: ListenerKind,
}

#[derive(Debug)]
pub(crate) struct CertSource {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Host names (exact or `*.suffix`) this certificate is selected for by SNI.
    pub names: Box<[Box<str>]>,
}

#[derive(Debug)]
pub(crate) struct SitePlan {
    pub name: Box<str>,
    /// Site headers, applied to every response first.
    pub headers: Box<[HeaderOp]>,
    pub routes: Block,
    pub errors: Box<[ErrorRoutePlan]>,
    /// `h3=":443"; ma=86400` when the site serves HTTP/3; added to h1/h2 TLS responses.
    pub alt_svc: Option<Box<[u8]>>,
}

#[derive(Debug)]
pub(crate) struct ErrorRoutePlan {
    /// Empty = every status.
    pub statuses: SmallVec<[Status; 4]>,
    pub routes: Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockKind {
    /// Every step whose `when` holds runs, in order, until a terminal one answers.
    Seq,
    /// Only the first step whose `when` holds runs; then the block is left.
    First,
}

#[derive(Debug)]
pub(crate) struct Block {
    pub kind: BlockKind,
    pub steps: Box<[Step]>,
}

#[derive(Debug)]
pub(crate) struct Step {
    pub name: Option<Box<str>>,
    /// `None` = always. Constant-true matchers are folded to `None`, constant-false steps are
    /// dropped at compile time.
    pub when: Option<Cond>,
    pub action: Action,
}

#[derive(Debug)]
pub(crate) enum Action {
    /// Simultaneous assignment: every template is expanded before any var is written.
    Set(Box<[(VarId, Template)]>),
    Rewrite(Template),
    StripPrefix(Box<[u8]>),
    TryFiles(FileProbe),
    ResponseHeaders(Box<[HeaderOp]>),
    RequestHeaders(Box<[HeaderOp]>),
    Encode(EncodingSet),
    Block(Block),
    Answer(Terminal),
}

/// Actions that answer the request. A step holding one ends routing when its `when` holds.
#[derive(Debug)]
pub(crate) enum Terminal {
    Proxy(ProxyPlan),
    Files(FilesPlan),
    Respond {
        status: Option<Status>,
        body: Template,
    },
    /// `to` expands to a Location that the redirect refuses (400) if it starts with `//` or
    /// `/\` or holds a control character, whatever the config's matchers did.
    Redirect {
        status: Status,
        to: Template,
    },
    Error(Status),
}

/// A header op from the config: set (`Some`) or remove (`None`). Names are validated and may
/// not be framing headers (the codec owns those).
#[derive(Debug)]
pub(crate) struct HeaderOp {
    pub name: HeaderName,
    pub value: Option<Template>,
}

#[derive(Debug)]
pub(crate) struct FileProbe {
    pub root: Template,
    pub paths: Box<[Template]>,
}

#[derive(Debug)]
pub(crate) struct ProxyPlan {
    pub upstream: UpstreamId,
    /// Defaults first (X-Forwarded-*), then the config's, so the config can override or remove
    /// a default.
    pub headers: Box<[HeaderOp]>,
    pub dial_timeout: Duration,
    pub response_header_timeout: Option<Duration>,
    pub tunnel_idle: Option<Duration>,
}

/// One origin. Proxy steps naming the same origin share its per-core connection pools.
#[derive(Debug)]
pub(crate) struct UpstreamPlan {
    pub id: UpstreamId,
    pub host: Box<str>,
    pub port: u16,
    /// Literal IPs are resolved at compile time; names (`storage`, `localhost`) when dialled,
    /// cached per core with a TTL, so a name that does not resolve yet (tailscale down at
    /// boot) never fails a load.
    pub addr: OriginAddr,
    pub tls: Option<UpstreamTls>,
    pub idle: Duration,
    pub max_idle_per_core: u16,
}

#[derive(Debug)]
pub(crate) enum OriginAddr {
    Ip(SocketAddr),
    Name,
}

#[derive(Debug)]
pub(crate) struct UpstreamTls {
    /// `None` for IP origins (no SNI).
    pub server_name: Option<Box<str>>,
    pub verify: bool,
}

#[derive(Debug)]
pub(crate) struct FilesPlan {
    pub root: Template,
    pub precompressed: SmallVec<[Encoding; 3]>,
    pub etag_sidecar: Option<Box<[u8]>>,
    pub index: Box<[Box<[u8]>]>,
}

/// A config problem, with the JSON pointer of the value that caused it.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub(crate) file: Option<PathBuf>,
    /// JSON pointer (RFC 6901) into `file`; empty for the document itself.
    pub(crate) pointer: String,
    /// The site's `name`, when the value is inside one.
    pub(crate) site: Option<String>,
    /// The step path inside the site or fragment: each step's `name`, or its index when it has
    /// none (`rewrites/try_files`, `errors[0]/2`).
    pub(crate) step: Option<String>,
    pub(crate) message: String,
    pub(crate) severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    Error,
    Warning,
}

impl Diagnostic {
    pub(crate) fn error(
        file: Option<&Path>,
        pointer: impl Into<String>,
        message: impl Into<String>,
    ) -> Diagnostic {
        Diagnostic {
            file: file.map(Path::to_path_buf),
            pointer: pointer.into(),
            site: None,
            step: None,
            message: message.into(),
            severity: Severity::Error,
        }
    }

    /// Whether the config is unusable because of this (warnings never fail a check).
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }

    /// Fills `site` and `step` from the document the pointer points into, so a message about
    /// `/sites/3/routes/1/when` names the site and step a person wrote.
    pub(crate) fn locate(mut self, doc: &serde_json::Value) -> Diagnostic {
        let (site, step) = locate(doc, &self.pointer);
        self.site = site;
        self.step = step;
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

impl std::fmt::Display for Diagnostic {
    /// `<file>:<pointer>: <site>/<step>: <message>`, leaving out the parts that are unknown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.severity == Severity::Warning {
            f.write_str("warning: ")?;
        }
        if let Some(file) = &self.file {
            write!(f, "{}", file.display())?;
            if !self.pointer.is_empty() {
                write!(f, ":{}", self.pointer)?;
            }
            f.write_str(": ")?;
        } else if !self.pointer.is_empty() {
            write!(f, "{}: ", self.pointer)?;
        }
        match (&self.site, &self.step) {
            (Some(site), Some(step)) => write!(f, "{site}/{step}: ")?,
            (Some(site), None) => write!(f, "{site}: ")?,
            (None, Some(step)) => write!(f, "{step}: ")?,
            (None, None) => {}
        }
        f.write_str(&self.message)
    }
}

/// `upstreamer check`: parse + compile, never touching certificates, roots or sockets.
///
/// Validates the schema of the input file (and its `version`/`fragment` number). Compiling
/// (templates, matchers, includes, listeners and the expected ports) is [`compile::compile`]'s.
pub(crate) fn check(input: crate::CheckInput) -> Result<crate::CheckReport, Vec<Diagnostic>> {
    use crate::config::{self, SchemaError};

    fn read(path: &Path) -> Result<Vec<u8>, Vec<Diagnostic>> {
        std::fs::read(path).map_err(|e| {
            vec![Diagnostic::error(
                Some(path),
                "",
                format!("cannot read: {e}"),
            )]
        })
    }
    fn schema(path: &Path, bytes: &[u8], e: SchemaError) -> Vec<Diagnostic> {
        let mut message = e.message;
        if e.line > 0 {
            message.push_str(&format!(" (line {}, column {})", e.line, e.column));
        }
        let diagnostic = Diagnostic::error(Some(path), e.pointer, message);
        vec![match serde_json::from_slice(bytes) {
            Ok(doc) => diagnostic.locate(&doc),
            Err(_) => diagnostic,
        }]
    }

    match input {
        crate::CheckInput::Config { path, expect: _ } => {
            let bytes = read(&path)?;
            let config = config::parse_config(&bytes).map_err(|e| schema(&path, &bytes, e))?;
            if config.version != 1 {
                let message = format!(
                    "unsupported config version {}; this upstreamer reads version 1",
                    config.version
                );
                return Err(vec![Diagnostic::error(Some(&path), "/version", message)]);
            }
            let steps = config
                .sites
                .iter()
                .map(|site| {
                    count_steps(&site.routes)
                        + site
                            .errors
                            .iter()
                            .map(|e| count_steps(&e.routes))
                            .sum::<usize>()
                })
                .sum();
            Ok(crate::CheckReport {
                sites: config.sites.len(),
                steps,
                warnings: Vec::new(),
            })
        }
        crate::CheckInput::Fragment(path) => {
            let bytes = read(&path)?;
            let fragment = config::parse_fragment(&bytes).map_err(|e| schema(&path, &bytes, e))?;
            if fragment.fragment != 1 {
                let message = format!(
                    "unsupported fragment version {}; this upstreamer reads version 1",
                    fragment.fragment
                );
                return Err(vec![Diagnostic::error(Some(&path), "/fragment", message)]);
            }
            let steps = count_steps(&fragment.routes)
                + fragment
                    .errors
                    .iter()
                    .map(|e| count_steps(&e.routes))
                    .sum::<usize>();
            Ok(crate::CheckReport {
                sites: 0,
                steps,
                warnings: Vec::new(),
            })
        }
    }
}

fn count_steps(steps: &[crate::config::Step]) -> usize {
    use crate::config::Action;
    steps
        .iter()
        .map(|step| {
            1 + match &step.action {
                Action::Routes(nested) | Action::FirstOf(nested) => count_steps(nested),
                _ => 0,
            }
        })
        .sum()
}

impl Plan {
    /// Host routing for a request on `listener`. `None` -> 421 on TLS listeners, 404 on
    /// cleartext ones.
    pub fn site_for(&self, listener: &ListenerKey, host: &[u8]) -> Option<(SiteId, &SitePlan)> {
        todo!()
    }
}
