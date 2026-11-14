//! Observations of one probe, normalised so that only differences that matter remain, and the
//! comparison of Caddy's with upstreamer's.
//!
//! Every normalisation names what it relies on. "Tradeoffs accepted" is the section of the
//! design rationale (`design/candidate-a/rationale.md`) that lists the deliberate differences
//! from Caddy.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;

use super::origin::Seen;
use super::support;

/// A response as the client read it.
pub struct Response {
    /// 0 when no response head arrived.
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
    /// For an event stream: whether the first event arrived while the origin held the second.
    pub streamed: Option<bool>,
    /// For an upgrade: whether bytes sent after the 101 came back.
    pub echoed: Option<bool>,
}

impl Response {
    pub fn none(read: &[u8], closed: bool) -> Response {
        let what = if closed { "closed" } else { "timed out" };
        Response {
            status: 0,
            head: format!("({what} after {} bytes)", read.len()),
            body: read.to_vec(),
            streamed: None,
            echoed: None,
        }
    }
}

/// One probe's answer, normalised.
pub struct Observation {
    pub status: u16,
    /// Lowercase names, sorted by name; values of one name in the order they came.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub upstream: Vec<Seen>,
    pub streamed: Option<bool>,
    pub echoed: Option<bool>,
}

/// One way in which Caddy and upstreamer answered a probe differently.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(deny_unknown_fields)]
pub struct Difference {
    pub site: String,
    pub probe: String,
    pub field: String,
    pub caddy: String,
    pub upstreamer: String,
}

impl Observation {
    /// Normalises a response and what the origins read. `names` replaces addresses that
    /// change from run to run (ports, temporary directories) with stable names.
    pub fn new(response: Response, upstream: Vec<Seen>, names: &[(String, String)]) -> Self {
        let rename = |text: &str| {
            names
                .iter()
                .fold(text.to_owned(), |text, (from, to)| text.replace(from, to))
        };
        let mut fields = parse_fields(&response.head);
        let encoding = fields
            .iter()
            .find(|(n, _)| n == "content-encoding")
            .map(|(_, v)| v.clone());
        let body = decoded(encoding.as_deref(), response.body);
        fields = normalise_response(fields);
        let upstream = upstream
            .into_iter()
            .map(|seen| Seen {
                origin: seen.origin,
                line: rename(&seen.line),
                headers: normalise_upstream(seen.headers)
                    .into_iter()
                    .map(|(n, v)| (n, rename(&v)))
                    .collect(),
                body: seen.body,
            })
            .collect();
        Observation {
            status: response.status,
            headers: fields.into_iter().map(|(n, v)| (n, rename(&v))).collect(),
            body: match String::from_utf8(body) {
                Ok(text) => rename(&text).into_bytes(),
                Err(binary) => binary.into_bytes(),
            },
            upstream,
            streamed: response.streamed,
            echoed: response.echoed,
        }
    }

    /// The observation as text, for the dump the tests write beside their failures.
    pub fn show(&self) -> String {
        let mut out = format!("{}\n", self.status);
        for (name, value) in &self.headers {
            out.push_str(&format!("  {name}: {value}\n"));
        }
        out.push_str(&format!("  body: {}\n", show_body(&self.body)));
        if let Some(streamed) = self.streamed {
            out.push_str(&format!("  streamed: {streamed}\n"));
        }
        if let Some(echoed) = self.echoed {
            out.push_str(&format!("  echoed: {echoed}\n"));
        }
        for seen in &self.upstream {
            out.push_str(&format!("  upstream {} {}\n", seen.origin, seen.line));
            for (name, value) in &seen.headers {
                out.push_str(&format!("    {name}: {value}\n"));
            }
            out.push_str(&format!("    body: {}\n", show_body(&seen.body)));
        }
        out
    }
}

fn parse_fields(head: &str) -> Vec<(String, String)> {
    head.lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}

/// The body's representation data: a gzip or zstd body that decodes is compared decoded.
///
/// Relies on RFC 9110 §8.4.1: a content coding is a transformation of the same representation,
/// and two compressors (or two levels of one) produce different bytes for it. The
/// Content-Encoding field itself is still compared. Precompressed sidecars in the fixture trees
/// are not real archives, so they fail to decode and are compared byte for byte.
fn decoded(encoding: Option<&str>, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    let ok = match encoding {
        Some("gzip") => flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut out)
            .is_ok(),
        Some("zstd") => zstd::stream::read::Decoder::new(&body[..])
            .and_then(|mut d| d.read_to_end(&mut out))
            .is_ok(),
        _ => false,
    };
    if ok { out } else { body }
}

/// Fields dropped from both sides' responses, with what each relies on:
///
/// - `date`: the clock (the unit's brief: drop Date).
/// - `server`: Tradeoffs accepted, "No `Server` header is sent."
/// - `content-length`, `transfer-encoding`: RFC 9112 §6, framing delimits the message on one
///   connection; the delivered body is compared instead.
/// - `connection`, `keep-alive`: RFC 9110 §7.6.1, per-hop connection management.
const DROPPED: [&str; 6] = [
    "date",
    "server",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
];

/// ETag values written by the build beside a file (`.etag` sidecars in `trees/`) and the
/// origins' ETag are kept. Any other ETag is a file server's own and becomes
/// `(server default etag)`. Relies on Tradeoffs accepted,
/// "Default ETags differ, though sidecar ETags are identical."
fn sidecar_etags() -> &'static BTreeSet<String> {
    static ETAGS: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    ETAGS.get_or_init(|| {
        let mut etags = BTreeSet::new();
        let mut dirs = vec![super::harness::dir().join("trees")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "etag") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    etags.insert(text.trim().to_owned());
                }
            }
        }
        etags
    })
}

fn normalise_etag(value: &str) -> String {
    let strong = value.strip_prefix("W/").unwrap_or(value);
    if strong == super::origin::ETAG || sidecar_etags().contains(strong) {
        value.to_owned()
    } else {
        "(server default etag)".to_owned()
    }
}

/// Every Vary field merged into one, as a sorted set of lowercase tokens. Relies on Tradeoffs
/// accepted, "The Vary token is merged."
fn merge_vary(fields: &mut Vec<(String, String)>) {
    let tokens: BTreeSet<String> = fields
        .iter()
        .filter(|(n, _)| n == "vary")
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    fields.retain(|(n, _)| n != "vary");
    if !tokens.is_empty() {
        let merged: Vec<String> = tokens.into_iter().collect();
        fields.push(("vary".to_owned(), merged.join(", ")));
    }
}

fn normalise_response(mut fields: Vec<(String, String)>) -> Vec<(String, String)> {
    fields.retain(|(n, _)| !DROPPED.contains(&n.as_str()));
    merge_vary(&mut fields);
    for (name, value) in &mut fields {
        if name == "etag" {
            *value = normalise_etag(value);
        }
    }
    // Relies on Tradeoffs accepted, "All response header ops apply after the handler": the
    // order of fields of different names carries no meaning, and the two servers apply
    // header operations at different times.
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields
}

/// Fields dropped from what the origins read, as for responses: framing (RFC 9112 §6) and
/// per-hop connection options other than `upgrade` (RFC 9110 §7.6.1).
fn normalise_upstream(mut fields: Vec<(String, String)>) -> Vec<(String, String)> {
    fields.retain(|(n, _)| {
        !matches!(
            n.as_str(),
            "content-length" | "transfer-encoding" | "keep-alive"
        )
    });
    for (name, value) in &mut fields {
        if name == "connection" {
            let options: Vec<String> = value
                .split(',')
                .map(|o| o.trim().to_ascii_lowercase())
                .filter(|o| !matches!(o.as_str(), "keep-alive" | "close" | ""))
                .collect();
            *value = options.join(", ");
        }
    }
    fields.retain(|(n, v)| n != "connection" || !v.is_empty());
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields
}

/// How a body is shown in a difference: its length, a hash prefix, and its start.
fn show_body(body: &[u8]) -> String {
    if body.is_empty() {
        return "(empty)".to_owned();
    }
    let text = String::from_utf8_lossy(&body[..body.len().min(72)]);
    format!(
        "{} bytes, sha256 {}, {:?}",
        body.len(),
        &support::sha256(body)[..12],
        text
    )
}

fn values(fields: &[(String, String)], name: &str) -> String {
    let values: Vec<&str> = fields
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
        .collect();
    if values.is_empty() {
        "(absent)".to_owned()
    } else {
        values.join(" | ")
    }
}

fn names(a: &[(String, String)], b: &[(String, String)]) -> BTreeSet<String> {
    a.iter().chain(b).map(|(n, _)| n.clone()).collect()
}

fn show_flag(flag: Option<bool>) -> String {
    match flag {
        None => "(not reached)".to_owned(),
        Some(true) => "yes".to_owned(),
        Some(false) => "no".to_owned(),
    }
}

/// Every difference between Caddy's and upstreamer's observation of one probe.
pub fn differences(
    site: &str,
    probe: &str,
    caddy: &Observation,
    ours: &Observation,
) -> Vec<Difference> {
    let mut out = Vec::new();
    let mut differ = |field: String, c: String, u: String| {
        if c != u {
            out.push(Difference {
                site: site.to_owned(),
                probe: probe.to_owned(),
                field,
                caddy: c,
                upstreamer: u,
            });
        }
    };
    differ(
        "status".into(),
        caddy.status.to_string(),
        ours.status.to_string(),
    );
    for name in names(&caddy.headers, &ours.headers) {
        differ(
            format!("header {name}"),
            values(&caddy.headers, &name),
            values(&ours.headers, &name),
        );
    }
    differ("body".into(), show_body(&caddy.body), show_body(&ours.body));
    differ(
        "streamed".into(),
        show_flag(caddy.streamed),
        show_flag(ours.streamed),
    );
    differ(
        "echoed".into(),
        show_flag(caddy.echoed),
        show_flag(ours.echoed),
    );

    let lines = |seen: &[Seen]| {
        let lines: Vec<String> = seen
            .iter()
            .map(|s| format!("{} {}", s.origin, s.line))
            .collect();
        if lines.is_empty() {
            "(none)".to_owned()
        } else {
            lines.join(" | ")
        }
    };
    if caddy.upstream.len() != ours.upstream.len() {
        differ(
            "upstream".into(),
            lines(&caddy.upstream),
            lines(&ours.upstream),
        );
        return out;
    }
    for (i, (c, u)) in caddy.upstream.iter().zip(&ours.upstream).enumerate() {
        let at = if i == 0 {
            String::new()
        } else {
            format!("[{i}]")
        };
        differ(
            format!("upstream{at} request"),
            format!("{} {}", c.origin, c.line),
            format!("{} {}", u.origin, u.line),
        );
        for name in names(&c.headers, &u.headers) {
            differ(
                format!("upstream{at} header {name}"),
                values(&c.headers, &name),
                values(&u.headers, &name),
            );
        }
        differ(
            format!("upstream{at} body"),
            show_body(&c.body),
            show_body(&u.body),
        );
    }
    out
}

/// `known.json`: every difference the corpus shows today, grouped by cause. A group is a
/// finding (upstreamer should change, or the fleet should decide) or an accepted difference
/// (the rationale's Tradeoffs accepted names it).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub kind: Kind,
    pub about: String,
    pub differences: Vec<Difference>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Finding,
    Accepted,
}

pub fn known() -> Vec<Group> {
    let path = super::harness::dir().join("known.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
}
