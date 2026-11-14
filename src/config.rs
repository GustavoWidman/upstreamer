//! The wire schema: the JSON the NixOS module writes (`builtins.toJSON` of the module's
//! options) and fragment generators emit. This is the single definition of the config
//! language; the Nix module types routes as plain JSON values and relies on
//! `upstreamer check` at build time instead of restating this schema in Nix.
//!
//! Only [`crate::plan::compile`] reads these types. Nothing in the hot path sees them, so a
//! schema change touches this file and the compiler and nothing else.

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
    pub sites: Vec<Site>,
}

fn yes() -> bool {
    true
}

/// Addresses used by sites that do not list their own. Plain sites and the HTTP->HTTPS
/// redirect use `http`; TLS sites use `https` (TCP, plus UDP when http3).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenDefaults {
    pub http: Vec<SocketAddr>,
    pub https: Vec<SocketAddr>,
}

impl Default for ListenDefaults {
    /// Wildcards (`[::]` is bound v6only), so startup never waits for an interface address.
    fn default() -> Self {
        let addrs = |port: u16| {
            vec![
                SocketAddr::from(([0, 0, 0, 0], port)),
                SocketAddr::from(([0u16; 8], port)),
            ]
        };
        ListenDefaults {
            http: addrs(80),
            https: addrs(443),
        }
    }
}

/// Parses a config file. With [`parse_fragment`], the only entry from bytes to schema types.
pub(crate) fn parse_config(bytes: &[u8]) -> Result<Config, SchemaError> {
    parse(bytes)
}

/// Parses a route fragment file (the target of an `include` step).
pub(crate) fn parse_fragment(bytes: &[u8]) -> Result<Fragment, SchemaError> {
    parse(bytes)
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

fn parse<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SchemaError> {
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

/// Downstream timeouts. Defaults: header 10s, keepAlive 75s, h2Idle 5m, shutdown 10s.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ServerTimeouts {
    /// From the first byte of a request to the end of its head (slowloris bound).
    pub header: Option<Dur>,
    /// Idle keep-alive connection (h1) before it is closed.
    pub keep_alive: Option<Dur>,
    pub h2_idle: Option<Dur>,
    /// Graceful shutdown: how long in-flight requests and tunnels may run after SIGTERM.
    pub shutdown: Option<Dur>,
}

/// Defaults: head 32 KiB, 100 header fields, h2 128 streams per connection.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Limits {
    pub max_head_bytes: Option<u32>,
    pub max_header_fields: Option<u16>,
    pub h2_max_streams: Option<u32>,
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
    /// Site headers: set (string) or removed (null) on every response the site sends,
    /// including error responses and redirects. Applied before step `headers`, so a step can
    /// override one for part of the site.
    #[serde(default)]
    pub headers: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub routes: Vec<Step>,
    #[serde(default)]
    pub errors: Vec<ErrorRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SiteTls {
    /// PEM certificate chain (fullchain.pem). A file that is missing or unreadable at load
    /// time does not fail the load: the site's names keep their previous certificate, or get
    /// a self-signed one, until a reload finds a usable pair.
    pub cert: PathBuf,
    pub key: PathBuf,
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
    #[serde(default)]
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
    /// Response header set (string) or remove (null), applied after the handler wrote its
    /// headers.
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
    // terminal
    Proxy(ProxySpec),
    Files(FilesSpec),
    Respond(RespondSpec),
    Redirect(RedirectSpec),
    Error(u16),
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
    "proxy",
    "files",
    "respond",
    "redirect",
    "error",
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
                        "headers" => Action::Headers(map.next_value()?),
                        "requestHeaders" => Action::RequestHeaders(map.next_value()?),
                        "encode" => Action::Encode(map.next_value()?),
                        "routes" => Action::Routes(map.next_value()?),
                        "firstOf" => Action::FirstOf(map.next_value()?),
                        "include" => Action::Include(map.next_value()?),
                        "proxy" => Action::Proxy(map.next_value()?),
                        "files" => Action::Files(map.next_value()?),
                        "respond" => Action::Respond(map.next_value()?),
                        "redirect" => Action::Redirect(map.next_value()?),
                        "error" => Action::Error(map.next_value()?),
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
    /// Unix seconds: holds once the clock has passed it (scheduled releases).
    pub after: Option<i64>,
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
    Full(ProxyFull),
}

impl<'de> Deserialize<'de> for ProxySpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ProxySpec;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an upstream URL or { to, tlsSkipVerify?, headers?, timeouts? }")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<ProxySpec, E> {
                Ok(ProxySpec::To(s.to_owned()))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<ProxySpec, E> {
                Ok(ProxySpec::To(s))
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<ProxySpec, A::Error> {
                Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(ProxySpec::Full)
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ProxyFull {
    /// `http://host:port` or `https://host:port`. One origin; no load balancing.
    pub to: String,
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Request headers to the upstream, after the defaults (Host passed through,
    /// X-Forwarded-For = {remote_host}, X-Forwarded-Proto = {scheme},
    /// X-Forwarded-Host = {host}). null removes one.
    #[serde(default)]
    pub headers: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub timeouts: ProxyTimeouts,
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
        parse(json.as_bytes())
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
        let e = parse_config(json).unwrap_err();
        assert_eq!(e.pointer, "/sites/0/routes/0/routes/0/when/path");
        assert_eq!(
            e.message,
            "invalid type: integer `7`, expected a string or a list of strings"
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let e = parse_config(br#"{"version":1,"sites":[]} x"#).unwrap_err();
        assert_eq!(e.message, "trailing characters");
    }
}
