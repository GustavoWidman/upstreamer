//! The wire schema: the JSON the NixOS module writes (`builtins.toJSON` of the module's
//! options) and fragment generators emit. This is the single definition of the config
//! language; the Nix module types routes as plain JSON values and relies on
//! `upstreamer check` at build time instead of restating this schema in Nix.
//!
//! Only [`crate::plan::compile`] reads these types. Nothing in the hot path sees them, so a
//! schema change touches this file and the compiler and nothing else.
//!
//! JSON comes from the NixOS module and from fragment generators, TOML from people. Both become
//! one `serde_json::Value` shape and go through the one deserializer below, so a TOML file
//! cannot mean something a JSON file could not.
//!
//! Every feature is a property of a proxy step or a step of its own: `proxy.to` takes a list
//! of origins or a discovery source, with `balance`, `retries`, `failStatuses` and `health`
//! beside it; `limit` answers 429 when its bucket is empty; `metrics` answers with the
//! Prometheus exposition. A feature no step names is absent from the plan.

pub(crate) mod acme;
pub(crate) mod toml;
pub(crate) mod trust;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Top level. `version` must be 1.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Config {
    pub version: u32,
    #[serde(default)]
    pub workers: Option<u16>,
    #[serde(default)]
    pub listen: ListenDefaults,
    /// HTTP/3 on every https address for sites that do not turn it off.
    #[serde(default = "yes")]
    pub http3: bool,
    #[serde(default)]
    pub timeouts: ServerTimeouts,
    #[serde(default)]
    pub limits: Limits,
    /// Peers whose forwarded client address is believed (a CDN, a load balancer).
    #[serde(default)]
    pub trusted_proxies: Option<trust::TrustSpec>,
    /// Settings shared by every site whose certificate comes from in-process ACME.
    #[serde(default)]
    pub acme: Option<acme::AcmeSettings>,
    pub sites: Vec<Site>,
}

fn yes() -> bool {
    true
}

/// Addresses used by sites that do not list their own. Plain sites and the HTTP->HTTPS
/// redirect use `http`; TLS sites use `https` (TCP, plus UDP when http3). Each list has its
/// own default, so `listen.http = [...]` alone is valid.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenDefaults {
    #[serde(default = "default_http")]
    pub http: Vec<SocketAddr>,
    #[serde(default = "default_https")]
    pub https: Vec<SocketAddr>,
}

/// Wildcards (`[::]` is bound v6only), so startup never waits for an interface address.
fn wildcards(port: u16) -> Vec<SocketAddr> {
    vec![
        SocketAddr::from(([0, 0, 0, 0], port)),
        SocketAddr::from(([0u16; 8], port)),
    ]
}

fn default_http() -> Vec<SocketAddr> {
    wildcards(80)
}

fn default_https() -> Vec<SocketAddr> {
    wildcards(443)
}

impl Default for ListenDefaults {
    fn default() -> Self {
        ListenDefaults {
            http: default_http(),
            https: default_https(),
        }
    }
}

/// How a document is written. Picked by file extension: `.toml` is TOML, anything else JSON
/// (the NixOS module writes `config.json`, generators write `*.json` fragments).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Json,
    Toml,
}

impl Format {
    pub fn of(path: &std::path::Path) -> Format {
        match path.extension() {
            Some(ext) if ext.eq_ignore_ascii_case("toml") => Format::Toml,
            _ => Format::Json,
        }
    }
}

/// A parsed document and what diagnostics need to point into it.
pub(crate) struct Parsed<T> {
    pub value: T,
    pub doc: Document,
}

/// The document as a JSON value (what `Diagnostic::locate` walks for site and step names),
/// and for TOML the source positions of its values, so a pointer can name a TOML line.
pub(crate) struct Document {
    pub value: serde_json::Value,
    pub positions: Option<toml::Positions>,
}

/// Parses a config file. With [`parse_fragment`], the only entry from bytes to schema types.
pub(crate) fn parse_config(format: Format, bytes: &[u8]) -> Result<Parsed<Config>, SchemaError> {
    parse(format, bytes)
}

/// Parses a route fragment file (the target of an `include` step).
pub(crate) fn parse_fragment(
    format: Format,
    bytes: &[u8],
) -> Result<Parsed<Fragment>, SchemaError> {
    parse(format, bytes)
}

/// The document of `bytes` alone, for locating diagnostics in a file whose schema check
/// failed. `None` when it does not even parse as `format`.
pub(crate) fn document(format: Format, bytes: &[u8]) -> Option<Document> {
    match format {
        Format::Json => Some(Document {
            value: serde_json::from_slice(bytes).ok()?,
            positions: None,
        }),
        Format::Toml => {
            let (value, positions) = toml::to_json(bytes).ok()?;
            Some(Document {
                value,
                positions: Some(positions),
            })
        }
    }
}

/// A document that is not valid JSON or does not fit the schema.
#[derive(Debug)]
pub(crate) struct SchemaError {
    /// JSON pointer (RFC 6901) of the value that failed, `""` for the document itself.
    pub pointer: String,
    /// 1-based position serde_json reports; 0 when it has none.
    pub line: usize,
    pub column: usize,
    /// What was wrong, without the position.
    pub message: String,
}

/// JSON is deserialized straight from the bytes, so its errors keep serde_json's line and
/// column; TOML is converted to the same value first and its positions come from the
/// conversion.
fn parse<T: de::DeserializeOwned>(format: Format, bytes: &[u8]) -> Result<Parsed<T>, SchemaError> {
    match format {
        Format::Json => {
            let value = parse_json(bytes)?;
            let doc = Document {
                value: serde_json::from_slice(bytes).unwrap_or_default(),
                positions: None,
            };
            Ok(Parsed { value, doc })
        }
        Format::Toml => {
            let (json, positions) = toml::to_json(bytes)?;
            let value = serde_path_to_error::deserialize(&json).map_err(|e| {
                let pointer = pointer(e.path());
                schema_error(pointer, &e.into_inner())
            })?;
            let doc = Document {
                value: json,
                positions: Some(positions),
            };
            Ok(Parsed { value, doc })
        }
    }
}

fn parse_json<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SchemaError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = serde_path_to_error::deserialize(&mut de).map_err(|e| {
        let pointer = pointer(e.path());
        let inner = e.into_inner();
        schema_error(pointer, &inner)
    })?;
    de.end().map_err(|e| schema_error(String::new(), &e))?;
    Ok(value)
}

fn schema_error(pointer: String, e: &serde_json::Error) -> SchemaError {
    let full = e.to_string();
    // serde_json appends " at line L column C"; the position is kept in its own fields.
    let message = match full.rfind(" at line ") {
        Some(i) if e.line() > 0 => full[..i].to_owned(),
        _ => full,
    };
    SchemaError {
        pointer,
        line: e.line(),
        column: e.column(),
        message,
    }
}

fn pointer(path: &serde_path_to_error::Path) -> String {
    use serde_path_to_error::Segment;
    let mut out = String::new();
    for segment in path.iter() {
        match segment {
            Segment::Seq { index } => {
                out.push('/');
                out.push_str(&index.to_string());
            }
            Segment::Map { key } | Segment::Enum { variant: key } => {
                out.push('/');
                out.push_str(&key.replace('~', "~0").replace('/', "~1"));
            }
            Segment::Unknown => {}
        }
    }
    out
}

/// Downstream timeouts. Defaults: header 10s, keepAlive 75s, shutdown 10s.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ServerTimeouts {
    /// From the first byte of a request to the end of its head (slowloris bound).
    pub header: Option<Dur>,
    /// How long a connection with no request in flight stays open: between requests on
    /// HTTP/1.1, without streams on HTTP/2, without packets on HTTP/3.
    pub keep_alive: Option<Dur>,
    /// Graceful shutdown: how long in-flight requests and tunnels may run after SIGTERM.
    pub shutdown: Option<Dur>,
}

/// Defaults: head 32 KiB, 100 header fields, 128 streams per HTTP/2 or HTTP/3 connection.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Limits {
    pub max_head_bytes: Option<u32>,
    pub max_header_fields: Option<u16>,
    /// Requests a client may have open at once on one HTTP/2 or HTTP/3 connection.
    pub max_streams: Option<u32>,
}

/// One virtual host (`services.upstreamer.virtualHosts.<name>`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Site {
    /// The NixOS attribute name; used in diagnostics and logs only.
    pub name: String,
    /// Exact names, `*.suffix` wildcards, or `*` (any host). Matched case-insensitively,
    /// without the port.
    pub hosts: Vec<String>,
    /// `None`: plain HTTP on the `http` addresses.
    #[serde(default)]
    pub tls: Option<SiteTls>,
    /// Overrides the default addresses for this site.
    #[serde(default)]
    pub listen: Option<Vec<SocketAddr>>,
    /// Site headers: set (string) or removed (`null` or `false`) on every response the site
    /// sends, including error responses and redirects. Applied before step `headers`, so a
    /// step can override one for part of the site.
    #[serde(default, deserialize_with = "header_edits")]
    pub headers: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub routes: Vec<Step>,
    #[serde(default)]
    pub errors: Vec<ErrorRoute>,
    /// Absolute path of the file this site's access log is appended to, one JSON object per
    /// finished request. Absent: the site logs nothing. Sites naming the same path share it.
    #[serde(default)]
    pub access_log: Option<PathBuf>,
}

/// Where a TLS site's certificate comes from: a `cert` and `key` pair of files, or `acme`
/// (in-process issuance and renewal). Exactly one of the two; the compiler says which is
/// missing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SiteTls {
    /// PEM certificate chain (fullchain.pem). A file that is missing or unreadable at load
    /// time does not fail the load: the site's names keep their previous certificate, or get
    /// a self-signed one, until a reload finds a usable pair.
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// The site's names get a certificate from an ACME CA, issued and renewed by this
    /// process. Self-signed until the first issuance, as a missing pair of files is.
    #[serde(default)]
    pub acme: Option<acme::SiteAcme>,
    #[serde(default = "yes")]
    pub redirect_http: bool,
    #[serde(default)]
    pub http3: Option<bool>,
}

/// A route fragment file, named by an `include` step. `fragment` must be 1.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Fragment {
    pub fragment: u32,
    /// Joined with the including site's headers; the same name in both is an error.
    #[serde(default, deserialize_with = "header_edits")]
    pub headers: BTreeMap<String, Option<String>>,
    pub routes: Vec<Step>,
    /// Appended to the including site's error routes.
    #[serde(default)]
    pub errors: Vec<ErrorRoute>,
}

/// `{ name?, when?, <exactly one action> }`. Deserialised by hand (see the `Deserialize` impl
/// below) so a step with two actions, none, or a misspelt key is an error at its own JSON
/// pointer instead of being read as its first action.
#[derive(Debug)]
pub(crate) struct Step {
    pub name: Option<String>,
    pub when: Option<Matcher>,
    pub action: Action,
}

/// Exactly one key per step. Non-terminal actions fall through to the next step; terminal ones
/// answer the request.
#[derive(Debug)]
pub(crate) enum Action {
    // non-terminal
    /// Assigns vars from templates. All templates of one `set` see the vars as they were
    /// before the step, so key order (which Nix sorts) never matters.
    Set(BTreeMap<String, String>),
    /// Replaces the path (and the query, if the template has a `?`).
    Rewrite(String),
    /// Removes a literal prefix from the path and from the forwarded target.
    StripPrefix(String),
    /// Rewrites the path to the first candidate that exists under `root`; no change if none.
    TryFiles(FileProbeSpec),
    /// Response header set (string) or remove (`null` or `false`), applied after the handler
    /// wrote its headers.
    Headers(BTreeMap<String, Option<String>>),
    /// Request header set or remove, applied before the handler runs.
    RequestHeaders(BTreeMap<String, Option<String>>),
    /// Encodings the response may be compressed with, in preference order.
    Encode(Vec<EncodingName>),
    /// Runs the nested steps in order.
    Routes(Vec<Step>),
    /// Runs only the first nested step whose `when` holds.
    FirstOf(Vec<Step>),
    /// Splices a fragment's routes here.
    Include(PathBuf),
    /// Takes a token from the bucket of the request's key, or answers 429.
    Limit(LimitSpec),
    // terminal
    Proxy(ProxySpec),
    Files(FilesSpec),
    Respond(RespondSpec),
    Redirect(RedirectSpec),
    Error(u16),
    /// The Prometheus exposition of the whole process.
    Metrics(MetricsSpec),
}

/// Every action key, in the order diagnostics list them.
pub(crate) const ACTIONS: &[&str] = &[
    "set",
    "rewrite",
    "stripPrefix",
    "tryFiles",
    "headers",
    "requestHeaders",
    "encode",
    "routes",
    "firstOf",
    "include",
    "limit",
    "proxy",
    "files",
    "respond",
    "redirect",
    "error",
    "metrics",
];

impl<'de> Deserialize<'de> for Step {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(StepVisitor)
    }
}

struct StepVisitor;

impl<'de> Visitor<'de> for StepVisitor {
    type Value = Step;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a route step: { name?, when?, <one action> }")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Step, A::Error> {
        let mut name = None;
        let mut when = None;
        let mut action: Option<(String, Action)> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => name = Some(map.next_value()?),
                "when" => when = Some(map.next_value()?),
                k if ACTIONS.contains(&k) => {
                    if let Some((first, _)) = &action {
                        return Err(de::Error::custom(format_args!(
                            "a step has exactly one action, found `{first}` and `{k}`"
                        )));
                    }
                    let value = match k {
                        "set" => Action::Set(map.next_value()?),
                        "rewrite" => Action::Rewrite(map.next_value()?),
                        "stripPrefix" => Action::StripPrefix(map.next_value()?),
                        "tryFiles" => Action::TryFiles(map.next_value()?),
                        "headers" => Action::Headers(map.next_value::<HeaderEdits>()?.0),
                        "requestHeaders" => {
                            Action::RequestHeaders(map.next_value::<HeaderEdits>()?.0)
                        }
                        "encode" => Action::Encode(map.next_value()?),
                        "routes" => Action::Routes(map.next_value()?),
                        "firstOf" => Action::FirstOf(map.next_value()?),
                        "include" => Action::Include(map.next_value()?),
                        "limit" => Action::Limit(map.next_value()?),
                        "proxy" => Action::Proxy(map.next_value()?),
                        "files" => Action::Files(map.next_value()?),
                        "respond" => Action::Respond(map.next_value()?),
                        "redirect" => Action::Redirect(map.next_value()?),
                        "error" => Action::Error(map.next_value()?),
                        "metrics" => Action::Metrics(map.next_value()?),
                        _ => unreachable!("ACTIONS lists every arm"),
                    };
                    action = Some((key, value));
                }
                other => {
                    return Err(de::Error::custom(format_args!(
                        "unknown key `{other}` in a step; expected `name`, `when` or one action ({})",
                        ACTIONS.join(", ")
                    )));
                }
            }
        }
        match action {
            Some((_, action)) => Ok(Step { name, when, action }),
            None => Err(de::Error::custom(format_args!(
                "a step needs one action ({})",
                ACTIONS.join(", ")
            ))),
        }
    }
}

/// All present keys must hold. `all`/`any`/`none` take lists, so Nix attribute-path merging
/// (`not.a = ..; not.b = ..;`) cannot silently change the meaning of a negation.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Matcher {
    /// Exact (`/blog`), prefix (`/api/*`), suffix (`*.etag`) or glob patterns over the clean,
    /// decoded path. Case-sensitive, like the file systems it guards.
    pub path: Option<OneOrMany>,
    /// Regex over the clean path; capture groups are `{re.N}` in this step's action.
    pub path_regex: Option<String>,
    pub method: Option<OneOrMany>,
    /// Globs over each header's field values joined with ", ".
    pub header: Option<BTreeMap<String, OneOrMany>>,
    pub header_regex: Option<BTreeMap<String, String>>,
    /// Any value of the key equals one of the given values.
    pub query: Option<BTreeMap<String, OneOrMany>>,
    /// A template, compared with `in` (equals one of) or `regex`.
    pub value: Option<String>,
    #[serde(rename = "in")]
    pub in_: Option<Vec<String>>,
    pub regex: Option<String>,
    /// Holds when one of `paths` names a regular file under `root` (a trailing `/` asks for a
    /// directory).
    pub file: Option<FileProbeSpec>,
    /// Holds once the clock has passed it (scheduled releases): unix seconds, or an RFC 3339
    /// date-time with an offset (`2026-12-01T00:00:00Z`).
    pub after: Option<After>,
    pub all: Option<Vec<Matcher>>,
    pub any: Option<Vec<Matcher>>,
    pub none: Option<Vec<Matcher>>,
}

/// A string or a list of strings.
#[derive(Debug)]
pub(crate) enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn as_slice(&self) -> &[String] {
        match self {
            OneOrMany::One(s) => std::slice::from_ref(s),
            OneOrMany::Many(v) => v,
        }
    }
}

impl<'de> Deserialize<'de> for OneOrMany {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = OneOrMany;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string or a list of strings")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<OneOrMany, E> {
                Ok(OneOrMany::One(s.to_owned()))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<OneOrMany, E> {
                Ok(OneOrMany::One(s))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<OneOrMany, A::Error> {
                Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
                    .map(OneOrMany::Many)
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileProbeSpec {
    pub root: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EncodingName {
    Br,
    Zstd,
    Gzip,
}

/// `"http://127.0.0.1:7979"` or the full object.
#[derive(Debug)]
pub(crate) enum ProxySpec {
    To(String),
    Full(Box<ProxyFull>),
}

impl<'de> Deserialize<'de> for ProxySpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ProxySpec;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "an upstream URL or { to, balance?, retries?, failStatuses?, health?, \
                     tlsSkipVerify?, headers?, timeouts? }",
                )
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<ProxySpec, E> {
                Ok(ProxySpec::To(s.to_owned()))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<ProxySpec, E> {
                Ok(ProxySpec::To(s))
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<ProxySpec, A::Error> {
                Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(|full| ProxySpec::Full(Box::new(full)))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ProxyFull {
    /// One origin URL (`http://host:port` or `https://host:port`), a list of origins, or a
    /// discovery source.
    pub to: Members,
    /// Default `roundRobin`. Ignored (and not compiled) for a single origin.
    #[serde(default)]
    pub balance: Option<BalanceSpec>,
    /// Further attempts on other origins for a request that may be replayed (idempotent
    /// method, body not consumed) after a failed attempt. Default 1 when the pool can hold
    /// more than one origin, else 0.
    #[serde(default)]
    pub retries: Option<u8>,
    /// Origin statuses that count as a failed attempt: they feed passive health and are
    /// retried like a refused connection. When the last attempt gets one, it is passed on.
    #[serde(default)]
    pub fail_statuses: Vec<u16>,
    #[serde(default)]
    pub health: Option<HealthSpec>,
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Request headers to the upstream, after the defaults (Host passed through,
    /// X-Forwarded-For = {remote_host}, X-Forwarded-Proto = {scheme},
    /// X-Forwarded-Host = {host}). `null` or `false` removes one.
    #[serde(default, deserialize_with = "header_edits")]
    pub headers: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub timeouts: ProxyTimeouts,
}

/// `"http://a:1"`, `["http://a:1", { url = "http://b:1", weight = 2 }]`, or
/// `{ kubernetes = { ... } }`. Deserialized by hand (string | array | map with one key) so
/// each shape's errors point at its own value.
#[derive(Debug)]
pub(crate) enum Members {
    One(String),
    List(Vec<Member>),
    Kubernetes(KubernetesSource),
}

#[derive(Debug)]
pub(crate) enum Member {
    Url(String),
    Weighted { url: String, weight: u16 },
}

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an origin URL, a list of origins, or { kubernetes = { .. } }")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Members, E> {
                Ok(Members::One(s.to_owned()))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<Members, E> {
                Ok(Members::One(s))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Members, A::Error> {
                Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
                    .map(Members::List)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let source = match map.next_key::<String>()? {
                    Some(key) if key == "kubernetes" => map.next_value()?,
                    Some(other) => {
                        return Err(de::Error::custom(format_args!(
                            "unknown origin source `{other}`; expected `kubernetes`"
                        )));
                    }
                    None => return Err(de::Error::custom("an origin source names one kind")),
                };
                if let Some(extra) = map.next_key::<String>()? {
                    return Err(de::Error::custom(format_args!(
                        "an origin source names one kind, found another key `{extra}`"
                    )));
                }
                Ok(Members::Kubernetes(source))
            }
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for Member {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Weighted {
            url: String,
            weight: u16,
        }
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Member;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an origin URL or { url, weight }")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Member, E> {
                Ok(Member::Url(s.to_owned()))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<Member, E> {
                Ok(Member::Url(s))
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Member, A::Error> {
                let Weighted { url, weight } =
                    Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(Member::Weighted { url, weight })
            }
        }
        d.deserialize_any(V)
    }
}

/// `"roundRobin" | "leastRequests" | "p2c" | { hash = "<template>" }`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum BalanceSpec {
    RoundRobin,
    /// Fewest requests in flight on this worker, ties broken round robin.
    LeastRequests,
    /// Two random origins, the one with fewer requests in flight on this worker.
    P2c,
    /// Maglev consistent hashing of the expanded template. An empty expansion falls back to
    /// round robin.
    Hash(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HealthSpec {
    #[serde(default)]
    pub passive: Option<PassiveSpec>,
    #[serde(default)]
    pub active: Option<ActiveSpec>,
}

/// Defaults for a pool: maxFails 3, cooldown 10s. `maxFails = 0` turns passive checks off.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct PassiveSpec {
    /// Consecutive failed attempts on one worker that eject the origin from every worker.
    #[serde(default)]
    pub max_fails: Option<u8>,
    /// How long an ejection lasts; doubles for each ejection in a row, up to 8x.
    #[serde(default)]
    pub cooldown: Option<Dur>,
}

/// An origin's probe. Belongs to the origin: two steps that probe one origin differently are a
/// config error, as two idle timeouts are.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ActiveSpec {
    /// Request path (with query, if any) of a `GET`.
    pub path: String,
    /// Host header of the probe. Default: the origin's host.
    #[serde(default)]
    pub host: Option<String>,
    /// Default 10s, jittered by up to 10%.
    #[serde(default)]
    pub interval: Option<Dur>,
    /// Default 2s; dial, TLS and response head together.
    #[serde(default)]
    pub timeout: Option<Dur>,
    /// Statuses that pass. Default: any 2xx or 3xx.
    #[serde(default)]
    pub expect: Option<Vec<u16>>,
    /// Consecutive passes that bring a failing origin back. Default 2.
    #[serde(default)]
    pub healthy_after: Option<u8>,
    /// Consecutive failures that take an origin out. Default 3.
    #[serde(default)]
    pub unhealthy_after: Option<u8>,
}

/// `{ namespace, service | selector, port, scheme?, serverName? }`. Parsed in every build so
/// `check` can say the build lacks the feature, instead of calling the key unknown.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct KubernetesSource {
    pub namespace: String,
    /// The Service whose EndpointSlices are the members. Exactly one of `service`, `selector`.
    #[serde(default)]
    pub service: Option<String>,
    /// A label selector over EndpointSlices (which carry their Service's labels): the members
    /// of every matching Service, merged.
    #[serde(default)]
    pub selector: Option<String>,
    /// The EndpointSlice port, by name or number.
    pub port: PortRef,
    /// `http` (default) or `https`.
    #[serde(default)]
    pub scheme: Option<String>,
    /// SNI and certificate name for `https` members (pod IPs have none of their own).
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum PortRef {
    Number(u16),
    Name(String),
}

/// `{ rate = "50/s", burst = 100, key = "{header.CF-Connecting-IP}", keys = 200000 }`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LimitSpec {
    /// `<count>/s`, `<count>/m` or `<count>/h`.
    pub rate: Rate,
    /// Requests a key may make at once after being idle. Default: the rate per second rounded
    /// up, at least 1.
    #[serde(default)]
    pub burst: Option<u32>,
    /// A template; each distinct expansion has its own bucket. A constant is one bucket for
    /// every request the step sees. Default `{remote_net}`.
    #[serde(default)]
    pub key: Option<String>,
    /// Buckets kept (memory: 8 bytes each). Default 65536. When every bucket near a new key
    /// is in use, the least-limited of them is replaced.
    #[serde(default)]
    pub keys: Option<u32>,
}

/// A request rate, parsed from `"<count>/(s|m|h)"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rate {
    pub count: u32,
    pub per: Duration,
}

impl<'de> Deserialize<'de> for Rate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_rate(&s)
            .ok_or_else(|| de::Error::custom(format!("invalid rate {s:?}: want <integer>/(s|m|h)")))
    }
}

fn parse_rate(s: &str) -> Option<Rate> {
    let (count, unit) = s.split_once('/')?;
    if count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let per = match unit {
        "s" => Duration::from_secs(1),
        "m" => Duration::from_secs(60),
        "h" => Duration::from_secs(3600),
        _ => return None,
    };
    Some(Rate {
        count: count.parse().ok()?,
        per,
    })
}

/// `{}` today. A struct (not a unit) so options can be added without a new spelling.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetricsSpec {}

/// Header edits: a string sets the field, `null` or `false` removes it. TOML has no null, so
/// `false` is the spelling a TOML file uses; JSON accepts both. `true` is an error. Used on
/// every header map (`Site::headers`, `Fragment::headers`, `Action::Headers`,
/// `Action::RequestHeaders`, `ProxyFull::headers`).
pub(crate) fn header_edits<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, Option<String>>, D::Error> {
    let edits = BTreeMap::<String, HeaderEdit>::deserialize(d)?;
    Ok(edits.into_iter().map(|(k, v)| (k, v.0)).collect())
}

/// A header map as a step's action.
struct HeaderEdits(BTreeMap<String, Option<String>>);

impl<'de> Deserialize<'de> for HeaderEdits {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        header_edits(d).map(HeaderEdits)
    }
}

struct HeaderEdit(Option<String>);

impl<'de> Deserialize<'de> for HeaderEdit {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = HeaderEdit;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a header value, or `false` or `null` to remove the header")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<HeaderEdit, E> {
                Ok(HeaderEdit(Some(s.to_owned())))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<HeaderEdit, E> {
                Ok(HeaderEdit(Some(s)))
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> Result<HeaderEdit, E> {
                match b {
                    false => Ok(HeaderEdit(None)),
                    true => Err(E::invalid_value(de::Unexpected::Bool(true), &self)),
                }
            }
            fn visit_unit<E: de::Error>(self) -> Result<HeaderEdit, E> {
                Ok(HeaderEdit(None))
            }
            fn visit_none<E: de::Error>(self) -> Result<HeaderEdit, E> {
                Ok(HeaderEdit(None))
            }
        }
        d.deserialize_any(V)
    }
}

/// When an `after` matcher starts to hold: unix seconds, written as a number or as an RFC 3339
/// date-time with an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct After(pub i64);

impl<'de> Deserialize<'de> for After {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = After;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unix seconds or an RFC 3339 date-time such as 2026-12-01T00:00:00Z")
            }
            fn visit_i64<E: de::Error>(self, n: i64) -> Result<After, E> {
                Ok(After(n))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<After, E> {
                i64::try_from(n)
                    .map(After)
                    .map_err(|_| E::invalid_value(de::Unexpected::Unsigned(n), &self))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<After, E> {
                rfc3339(s)
                    .map(After)
                    .ok_or_else(|| E::invalid_value(de::Unexpected::Str(s), &self))
            }
        }
        d.deserialize_any(V)
    }
}

/// Unix seconds of `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`; the fraction is dropped.
fn rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let digits = b.get(r)?;
        digits
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| digits.iter().fold(0, |n, d| n * 10 + i64::from(d - b'0')))
    };
    let sep = |i: usize, c: &[u8]| b.get(i).is_some_and(|x| c.contains(x));
    if !(sep(4, b"-") && sep(7, b"-") && sep(10, b"Tt ") && sep(13, b":") && sep(16, b":")) {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &frac[digits..];
    }
    let offset = match rest.as_bytes() {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let two = |a: u8, b: u8| {
                (a.is_ascii_digit() && b.is_ascii_digit())
                    .then(|| i64::from(a - b'0') * 10 + i64::from(b - b'0'))
            };
            let (h, m) = (two(*h1, *h2)?, two(*m1, *m2)?);
            if h > 23 || m > 59 {
                return None;
            }
            let secs = h * 3600 + m * 60;
            if *sign == b'+' { secs } else { -secs }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Defaults: dial 5s, idle 2m, responseHeader none, tunnelIdle none.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ProxyTimeouts {
    pub dial: Option<Dur>,
    /// From the end of the request head to the end of the response head.
    pub response_header: Option<Dur>,
    /// Pooled idle upstream connection lifetime. Belongs to the origin: two proxy steps to
    /// one origin with different values are a config error.
    pub idle: Option<Dur>,
    /// An upgraded connection (WebSocket, DERP) that carried nothing either way this long
    /// is closed.
    pub tunnel_idle: Option<Dur>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FilesSpec {
    pub root: String,
    /// Sidecars tried in this order when the client accepts the encoding:
    /// br -> `<file>.br`, zstd -> `<file>.zst`, gzip -> `<file>.gz`.
    #[serde(default)]
    pub precompressed: Vec<EncodingName>,
    /// Extension of the ETag sidecar (`.etag`): its content is the file's ETag.
    #[serde(default)]
    pub etag_sidecar: Option<String>,
    /// Directory index names. Default `["index.html"]`.
    #[serde(default)]
    pub index: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RespondSpec {
    /// Default: 200, or the error's status inside an error route.
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedirectSpec {
    pub to: String,
    pub status: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorRoute {
    /// Statuses this route handles; absent = every error.
    #[serde(default)]
    pub status: Option<Vec<u16>>,
    pub routes: Vec<Step>,
}

/// `"300ms"`, `"5s"`, `"2m"`, `"1h"`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dur(pub Duration);

impl<'de> Deserialize<'de> for Dur {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_duration(&s).map(Dur).ok_or_else(|| {
            serde::de::Error::custom(format!("invalid duration {s:?}: want <integer>(ms|s|m|h)"))
        })
    }
}

fn parse_duration(s: &str) -> Option<Duration> {
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().ok()?;
    Some(match unit {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n.checked_mul(60)?),
        "h" => Duration::from_secs(n.checked_mul(3600)?),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("300ms"), Some(Duration::from_millis(300)));
        assert_eq!(parse_duration("300s"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("5"), None);
        assert_eq!(parse_duration("s"), None);
        assert_eq!(parse_duration("5 s"), None);
        assert_eq!(parse_duration("-5s"), None);
    }

    fn step(json: &str) -> Result<Step, SchemaError> {
        parse_json(json.as_bytes())
    }

    fn config(json: &[u8]) -> Result<Config, SchemaError> {
        parse_config(Format::Json, json).map(|parsed| parsed.value)
    }

    #[test]
    fn step_actions() {
        let s = step(r#"{"name":"api","when":{"path":"/api/*"},"proxy":"http://127.0.0.1:1"}"#)
            .unwrap();
        assert_eq!(s.name.as_deref(), Some("api"));
        assert!(
            matches!(s.action, Action::Proxy(ProxySpec::To(ref to)) if to == "http://127.0.0.1:1")
        );
        let s = step(r#"{"proxy":{"to":"https://127.0.0.1:2","tlsSkipVerify":true}}"#).unwrap();
        assert!(matches!(s.action, Action::Proxy(ProxySpec::Full(ref p)) if p.tls_skip_verify));
        let s = step(r#"{"firstOf":[{"error":404}]}"#).unwrap();
        assert!(matches!(s.action, Action::FirstOf(ref steps) if steps.len() == 1));
    }

    #[test]
    fn step_rejects_two_actions() {
        let e = step(r#"{"proxy":"http://a:1","files":{"root":"/srv"}}"#).unwrap_err();
        assert_eq!(
            e.message,
            "a step has exactly one action, found `proxy` and `files`"
        );
    }

    #[test]
    fn step_rejects_no_action() {
        let e = step(r#"{"name":"x","when":{"path":"/"}}"#).unwrap_err();
        assert!(
            e.message.starts_with("a step needs one action"),
            "{}",
            e.message
        );
    }

    #[test]
    fn step_rejects_unknown_key() {
        let e = step(r#"{"proxi":"http://a:1"}"#).unwrap_err();
        assert!(
            e.message.starts_with("unknown key `proxi` in a step"),
            "{}",
            e.message
        );
    }

    #[test]
    fn error_pointer_reaches_nested_value() {
        let json = br#"{"version":1,"sites":[{"name":"a","hosts":["a"],"routes":[{"routes":[{"when":{"path":7},"error":404}]}]}]}"#;
        let e = config(json).unwrap_err();
        assert_eq!(e.pointer, "/sites/0/routes/0/routes/0/when/path");
        assert_eq!(
            e.message,
            "invalid type: integer `7`, expected a string or a list of strings"
        );
    }

    #[test]
    fn one_idle_timeout_and_one_stream_limit_for_every_protocol() {
        let parsed = config(
            br#"{"version":1,"sites":[],"timeouts":{"keepAlive":"30s"},"limits":{"maxStreams":64}}"#,
        )
        .unwrap();
        assert_eq!(
            parsed.timeouts.keep_alive.unwrap().0,
            Duration::from_secs(30)
        );
        assert_eq!(parsed.limits.max_streams, Some(64));
        for (json, pointer) in [
            (
                br#"{"version":1,"sites":[],"timeouts":{"h2Idle":"5m"}}"#.as_slice(),
                "/timeouts/h2Idle",
            ),
            (
                br#"{"version":1,"sites":[],"limits":{"h2MaxStreams":64}}"#,
                "/limits/h2MaxStreams",
            ),
        ] {
            let e = config(json).unwrap_err();
            assert_eq!(e.pointer, pointer);
            assert!(e.message.starts_with("unknown field"), "{}", e.message);
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let e = config(br#"{"version":1,"sites":[]} x"#).unwrap_err();
        assert_eq!(e.message, "trailing characters");
    }

    fn proxy(json: &str) -> ProxyFull {
        match step(&format!(r#"{{"proxy":{json}}}"#)).unwrap().action {
            Action::Proxy(ProxySpec::Full(full)) => *full,
            other => panic!("not a full proxy step: {other:?}"),
        }
    }

    #[test]
    fn false_or_null_removes_a_header_and_true_is_an_error() {
        let parsed = config(
            br#"{"version":1,"sites":[{"name":"a","hosts":["*"],
                "headers":{"Server":false,"X-Powered-By":null,"X-Frame-Options":"DENY"},
                "routes":[{"headers":{"Server":false}},{"requestHeaders":{"Cookie":false}},
                          {"proxy":{"to":"http://a:1","headers":{"X-Real-IP":false}}}]}]}"#,
        )
        .unwrap();
        let site = &parsed.sites[0];
        let edits: Vec<(&str, Option<&str>)> = site
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_deref()))
            .collect();
        assert_eq!(
            edits,
            [
                ("Server", None),
                ("X-Frame-Options", Some("DENY")),
                ("X-Powered-By", None)
            ]
        );
        assert!(matches!(&site.routes[0].action, Action::Headers(h) if h["Server"].is_none()));
        assert!(
            matches!(&site.routes[1].action, Action::RequestHeaders(h) if h["Cookie"].is_none())
        );
        assert!(matches!(
            &site.routes[2].action,
            Action::Proxy(ProxySpec::Full(p)) if p.headers["X-Real-IP"].is_none()
        ));

        let e = step(r#"{"headers":{"Server":true}}"#).unwrap_err();
        assert_eq!(e.pointer, "/headers/Server");
        assert!(e.message.contains("`false` or `null`"), "{}", e.message);
    }

    #[test]
    fn each_listen_list_has_its_own_default() {
        let parsed =
            config(br#"{"version":1,"listen":{"http":["0.0.0.0:8080"]},"sites":[]}"#).unwrap();
        assert_eq!(parsed.listen.http, ["0.0.0.0:8080".parse().unwrap()]);
        assert_eq!(
            parsed.listen.https,
            ["0.0.0.0:443".parse().unwrap(), "[::]:443".parse().unwrap()]
        );
    }

    #[test]
    fn after_reads_unix_seconds_or_rfc3339() {
        let after = |json: &str| -> Result<i64, String> {
            step(&format!(r#"{{"when":{{"after":{json}}},"error":404}}"#))
                .map(|s| s.when.unwrap().after.unwrap().0)
                .map_err(|e| e.message)
        };
        assert_eq!(after("1796083200"), Ok(1_796_083_200));
        assert_eq!(after(r#""2026-12-01T00:00:00Z""#), Ok(1_796_083_200));
        assert_eq!(after(r#""1994-11-06T08:49:37+01:00""#), Ok(784_108_177));
        assert_eq!(after(r#""2000-02-29t23:59:59.25-05:30""#), Ok(951_888_599));
        for bad in [
            r#""2026-12-01""#,
            r#""2026-12-01T00:00:00""#,
            r#""2026-02-29T00:00:00Z""#,
            r#""2026-13-01T00:00:00Z""#,
            r#""2026-12-01T24:00:00Z""#,
            r#""2026-12-01T00:00:00.Z""#,
            "true",
        ] {
            assert!(after(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn proxy_targets_take_one_origin_a_list_or_a_source() {
        assert!(
            matches!(proxy(r#"{"to":"http://a:1"}"#).to, Members::One(ref u) if u == "http://a:1")
        );
        let p = proxy(r#"{"to":["http://a:1",{"url":"http://b:1","weight":2}]}"#);
        let Members::List(list) = p.to else {
            panic!("a list")
        };
        assert!(matches!(&list[0], Member::Url(u) if u == "http://a:1"));
        assert!(matches!(&list[1], Member::Weighted { url, weight: 2 } if url == "http://b:1"));
        let p = proxy(
            r#"{"to":{"kubernetes":{"namespace":"web","service":"shop","port":"http","scheme":"https","serverName":"shop.web.svc"}}}"#,
        );
        let Members::Kubernetes(k) = p.to else {
            panic!("a source")
        };
        assert_eq!(
            (
                k.namespace.as_str(),
                k.service.as_deref(),
                k.selector.as_deref()
            ),
            ("web", Some("shop"), None)
        );
        assert!(matches!(k.port, PortRef::Name(ref n) if n == "http"));
        assert_eq!(k.scheme.as_deref(), Some("https"));
        assert_eq!(k.server_name.as_deref(), Some("shop.web.svc"));
        let p =
            proxy(r#"{"to":{"kubernetes":{"namespace":"web","selector":"app=shop","port":8080}}}"#);
        assert!(matches!(
            p.to,
            Members::Kubernetes(KubernetesSource {
                port: PortRef::Number(8080),
                ..
            })
        ));

        for (json, pointer, message) in [
            (
                r#"{"to":{"consul":{}}}"#,
                "/proxy/to",
                "unknown origin source `consul`; expected `kubernetes`",
            ),
            (
                r#"{"to":["http://a:1",{"url":"http://b:1","weight":2,"backup":true}]}"#,
                "/proxy/to/1/backup",
                "unknown field `backup`, expected `url` or `weight`",
            ),
            (
                r#"{"to":{"kubernetes":{"namespace":"web","port":80,"service":"a"},"dns":{}}}"#,
                "/proxy/to",
                "an origin source names one kind, found another key `dns`",
            ),
        ] {
            let e = step(&format!(r#"{{"proxy":{json}}}"#)).unwrap_err();
            assert_eq!(
                (e.pointer.as_str(), e.message.as_str()),
                (pointer, message),
                "{json}"
            );
        }
    }

    #[test]
    fn balancing_retries_and_health_sit_beside_the_target() {
        let p = proxy(
            r#"{"to":["http://a:1","http://b:1"],"balance":"leastRequests","retries":2,
                "failStatuses":[502,503],
                "health":{"passive":{"maxFails":5,"cooldown":"15s"},
                          "active":{"path":"/healthz","host":"a.internal","interval":"5s","timeout":"1s",
                                    "expect":[200],"healthyAfter":2,"unhealthyAfter":4}}}"#,
        );
        assert!(matches!(p.balance, Some(BalanceSpec::LeastRequests)));
        assert_eq!(
            (p.retries, p.fail_statuses.as_slice()),
            (Some(2), &[502, 503][..])
        );
        let health = p.health.unwrap();
        let passive = health.passive.unwrap();
        assert_eq!(passive.max_fails, Some(5));
        assert_eq!(passive.cooldown.unwrap().0, Duration::from_secs(15));
        let active = health.active.unwrap();
        assert_eq!(
            (active.path.as_str(), active.host.as_deref()),
            ("/healthz", Some("a.internal"))
        );
        assert_eq!(active.interval.unwrap().0, Duration::from_secs(5));
        assert_eq!(active.timeout.unwrap().0, Duration::from_secs(1));
        assert_eq!(active.expect.as_deref(), Some(&[200][..]));
        assert_eq!(
            (active.healthy_after, active.unhealthy_after),
            (Some(2), Some(4))
        );

        for (json, balance) in [
            (r#""roundRobin""#, "RoundRobin"),
            (r#""p2c""#, "P2c"),
            (r#"{"hash":"{cookie.cart}"}"#, "Hash(\"{cookie.cart}\")"),
        ] {
            let p = proxy(&format!(r#"{{"to":"http://a:1","balance":{json}}}"#));
            assert_eq!(format!("{:?}", p.balance.unwrap()), balance);
        }
        let e = step(r#"{"proxy":{"to":"http://a:1","balance":"leastConnections"}}"#).unwrap_err();
        assert_eq!(e.pointer, "/proxy/balance");
        assert_eq!(
            e.message,
            "unknown variant `leastConnections`, expected one of `roundRobin`, `leastRequests`, `p2c`, `hash`"
        );
    }

    #[test]
    fn limit_and_metrics_are_steps() {
        let s = step(r#"{"name":"api","limit":{"rate":"50/s","burst":100,"key":"{header.CF-Connecting-IP}","keys":200000}}"#)
            .unwrap();
        let Action::Limit(limit) = s.action else {
            panic!("a limit step")
        };
        assert_eq!(
            limit.rate,
            Rate {
                count: 50,
                per: Duration::from_secs(1)
            }
        );
        assert_eq!(limit.burst, Some(100));
        assert_eq!(limit.key.as_deref(), Some("{header.CF-Connecting-IP}"));
        assert_eq!(limit.keys, Some(200_000));
        let Action::Limit(limit) = step(r#"{"limit":{"rate":"5/m"}}"#).unwrap().action else {
            panic!("a limit step")
        };
        assert_eq!(limit.rate.per, Duration::from_secs(60));
        assert_eq!((limit.burst, limit.key, limit.keys), (None, None, None));
        assert_eq!(
            parse_rate("1/h").map(|r| r.per),
            Some(Duration::from_secs(3600))
        );

        let e = step(r#"{"limit":{"rate":"5/min"}}"#).unwrap_err();
        assert_eq!(e.pointer, "/limit/rate");
        assert_eq!(e.message, "invalid rate \"5/min\": want <integer>/(s|m|h)");
        for bad in ["/s", "x/s", "-1/s", "5", "5/"] {
            assert_eq!(parse_rate(bad), None, "{bad}");
        }

        let s = step(r#"{"when":{"path":"/metrics"},"metrics":{}}"#).unwrap();
        assert!(matches!(s.action, Action::Metrics(MetricsSpec {})));
        let e = step(r#"{"metrics":{"path":"/m"}}"#).unwrap_err();
        assert_eq!(e.pointer, "/metrics/path");
        assert!(
            e.message.starts_with("unknown field `path`"),
            "{}",
            e.message
        );
    }

    #[test]
    fn a_tls_site_names_files_or_acme() {
        let parsed = config(
            br#"{"version":1,"sites":[
                {"name":"files","hosts":["a"],"tls":{"cert":"/c.pem","key":"/k.pem"}},
                {"name":"acme","hosts":["b"],"tls":{"acme":{"email":"ops@example.com"}}}]}"#,
        )
        .unwrap();
        let files = parsed.sites[0].tls.as_ref().unwrap();
        assert_eq!(files.cert.as_deref(), Some(std::path::Path::new("/c.pem")));
        assert!(files.acme.is_none());
        let acme = parsed.sites[1].tls.as_ref().unwrap();
        assert!(acme.acme.is_some() && acme.cert.is_none() && acme.key.is_none());
    }

    #[test]
    fn format_follows_the_extension() {
        let of = |p: &str| Format::of(std::path::Path::new(p));
        assert_eq!(of("/etc/upstreamer/config.json"), Format::Json);
        assert_eq!(of("upstreamer.toml"), Format::Toml);
        assert_eq!(of("UPSTREAMER.TOML"), Format::Toml);
        assert_eq!(of("config"), Format::Json);
    }
}
