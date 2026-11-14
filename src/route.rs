//! The router: interprets a site's step program against an exchange and returns what should
//! answer it. Synchronous and deterministic: its only inputs besides the plan and the exchange
//! are the core's regex caches, the file catalog (existence checks for `file` and `tryFiles`,
//! cached forever for immutable /nix/store roots) and the coarse clock (`after`).
//!
//! It never does network IO and never awaits, so a core-local `RefCell` borrow of the caches
//! for its duration cannot be held across an await.
//!
//! Allocation: none once the exchange's arena, field buffer, var and capture slots and pending
//! op list have grown to the request's size (they are recycled with the exchange). Regex
//! searches use the core's caches and a stack slot array. File probes go to
//! [`Catalog::probe`].

use crate::exchange::{ASpan, Exchange, PendingOp};
use crate::files::catalog::Catalog;
use crate::msg::{HeaderName, Status};
use crate::plan::cond::Test;
use crate::plan::template::{MAX_CAPTURE, decoded_eq, query_values};
use crate::plan::{
    Action, Block, BlockKind, Cond, FileProbe, FilesPlan, HeaderOp, Plan, ProxyPlan, RegexId,
    SitePlan, Terminal,
};
use crate::runtime::RegexCaches;
use regex_automata::Input;
use regex_automata::util::primitives::NonMaxUsize;
use smallvec::SmallVec;

/// Core-local state routing may consult.
pub(crate) struct Effects<'c> {
    pub regex: &'c mut RegexCaches,
    pub catalog: &'c mut Catalog,
    /// Unix seconds, from the core's coarse clock.
    pub now: i64,
}

/// The terminal decision, with every template already expanded into the exchange's arena.
#[derive(Debug)]
pub(crate) enum Outcome<'p> {
    Proxy(&'p ProxyPlan),
    Files { plan: &'p FilesPlan, root: ASpan },
    Respond { status: Status, body: ASpan },
    Redirect { status: Status, location: ASpan },
    Error(Status),
}

/// Runs the site's routes. Reaching the end without a terminal step is `Error(404)`.
pub(crate) fn run<'p>(
    plan: &'p Plan,
    site: &'p SitePlan,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Outcome<'p> {
    match run_block(plan, &site.routes, ex, fx) {
        Flow::Answer(o) => o,
        Flow::Next => Outcome::Error(Status::NOT_FOUND),
    }
}

/// Runs the first error route whose statuses include `ex.error`'s status. Pending header ops
/// and vars from the main route are kept (the error route's ops apply after them). `None`
/// when no error route matches, or the one that does reaches its end without answering: the
/// pipeline then answers with a bare status response.
pub(crate) fn run_error<'p>(
    plan: &'p Plan,
    site: &'p SitePlan,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Option<Outcome<'p>> {
    let status = ex.error?.status;
    let route = site
        .errors
        .iter()
        .find(|r| r.statuses.is_empty() || r.statuses.contains(&status))?;
    match run_block(plan, &route.routes, ex, fx) {
        Flow::Answer(o) => Some(o),
        Flow::Next => None,
    }
}

enum Flow<'p> {
    Next,
    Answer(Outcome<'p>),
}

fn run_block<'p>(
    plan: &'p Plan,
    block: &'p Block,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Flow<'p> {
    for step in block.steps.iter() {
        ex.captures.clear();
        if let Some(cond) = &step.when
            && !eval(plan, cond, ex, fx)
        {
            continue;
        }
        if let Flow::Answer(outcome) = apply(plan, &step.action, ex, fx) {
            return Flow::Answer(outcome);
        }
        if block.kind == BlockKind::First {
            break;
        }
    }
    Flow::Next
}

/// Evaluates a matcher. Short-circuits; the compiler orders an `All` cheapest first
/// (path/method/constant tests before header scans, regexes and file probes).
fn eval(plan: &Plan, cond: &Cond, ex: &mut Exchange, fx: &mut Effects<'_>) -> bool {
    match cond {
        Cond::All(conds) => conds.iter().all(|c| eval(plan, c, ex, fx)),
        Cond::Any(conds) => conds.iter().any(|c| eval(plan, c, ex, fx)),
        Cond::None(conds) => !conds.iter().any(|c| eval(plan, c, ex, fx)),
        Cond::Test(t) => test(plan, t, ex, fx),
    }
}

fn test(plan: &Plan, t: &Test, ex: &mut Exchange, fx: &mut Effects<'_>) -> bool {
    match t {
        Test::Path(patterns) => patterns.matches(ex.req.path().as_bytes()),
        Test::PathRegex { regex, captures } => {
            if !*captures {
                return is_match(plan, fx, *regex, ex.req.path().as_bytes());
            }
            let hay = ex.arena.push(ex.req.path().as_bytes());
            capture(plan, fx, *regex, ex, hay)
        }
        Test::Method(set) => set.contains(ex.req.method, ex.req.method_bytes()),
        Test::Header { name, globs } => {
            joined(ex, name, |v| globs.iter().any(|g| g.matches(v))).unwrap_or(false)
        }
        Test::HeaderRegex { name, regex } => {
            joined(ex, name, |v| is_match(plan, fx, *regex, v)).unwrap_or(false)
        }
        Test::Query { key, values } => {
            query_values(ex.req.query(), key).any(|v| values.iter().any(|want| decoded_eq(v, want)))
        }
        Test::ValueIn { value, set } => {
            let span = value.expand(ex);
            let v = ex.arena.get(span);
            set.iter().any(|s| **s == *v)
        }
        Test::ValueRegex {
            value,
            regex,
            captures,
        } => {
            let hay = value.expand(ex);
            if !*captures {
                return is_match(plan, fx, *regex, ex.arena.get(hay));
            }
            capture(plan, fx, *regex, ex, hay)
        }
        Test::File(probe) => probe_first(probe, ex, fx).is_some(),
        Test::After(t) => fx.now >= *t,
    }
}

fn is_match(plan: &Plan, fx: &mut Effects<'_>, id: RegexId, hay: &[u8]) -> bool {
    let i = id.0 as usize;
    plan.regexes[i]
        .search_half_with(&mut fx.regex.caches[i], &Input::new(hay).earliest(true))
        .is_some()
}

/// Searches the arena span `hay` and, on a match, records its groups as `ex.captures`
/// (spans into the same arena, so nothing is copied).
fn capture(plan: &Plan, fx: &mut Effects<'_>, id: RegexId, ex: &mut Exchange, hay: ASpan) -> bool {
    let i = id.0 as usize;
    let mut slots: [Option<NonMaxUsize>; 2 * (MAX_CAPTURE as usize + 1)] = Default::default();
    let slots = &mut slots[..2 * groups(plan, id)];
    let input = Input::new(ex.arena.get(hay));
    if plan.regexes[i]
        .search_slots_with(&mut fx.regex.caches[i], &input, slots)
        .is_none()
    {
        return false;
    }
    ex.captures.clear();
    for [start, end] in slots.as_chunks::<2>().0 {
        ex.captures.push(match (start, end) {
            (Some(s), Some(e)) => Some(ASpan {
                start: hay.start + s.get() as u32,
                end: hay.start + e.get() as u32,
            }),
            _ => None,
        });
    }
    true
}

/// Groups a step may read, group 0 included; the compiler rejects `{re.N}` above
/// [`MAX_CAPTURE`].
fn groups(plan: &Plan, id: RegexId) -> usize {
    plan.regexes[id.0 as usize]
        .captures_len()
        .min(MAX_CAPTURE as usize + 1)
}

/// Calls `f` with the field's values joined with ", " (in place for a single field, in the
/// arena for several). `None` when the request has no such field.
fn joined<R>(ex: &mut Exchange, name: &HeaderName, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
    let mut values = ex.req.fields.values(name);
    let first = values.next()?;
    if values.next().is_none() {
        return Some(f(first));
    }
    let fields = &ex.req.fields;
    let span = ex.arena.build(|out| {
        for (i, v) in fields.values(name).enumerate() {
            if i > 0 {
                out.extend_from_slice(b", ");
            }
            out.extend_from_slice(v);
        }
    });
    Some(f(ex.arena.get(span)))
}

/// The first candidate that names an existing file under the root, as an arena span.
fn probe_first(probe: &FileProbe, ex: &mut Exchange, fx: &mut Effects<'_>) -> Option<ASpan> {
    let root = probe.root.expand(ex);
    for path in probe.paths.iter() {
        let rel = path.expand(ex);
        if fx.catalog.probe(ex.arena.get(root), ex.arena.get(rel)) {
            return Some(rel);
        }
    }
    None
}

fn apply<'p>(
    plan: &'p Plan,
    action: &'p Action,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Flow<'p> {
    match action {
        Action::Set(assigns) => {
            let mut spans: SmallVec<[ASpan; 8]> = SmallVec::new();
            for (_, template) in assigns.iter() {
                spans.push(template.expand(ex));
            }
            for ((var, _), span) in assigns.iter().zip(spans) {
                ex.vars[var.0 as usize] = Some(span);
            }
        }
        Action::Rewrite(template) => {
            let span = template.expand(ex);
            if ex.req.rewrite(ex.arena.get(span)).is_err() {
                return Flow::Answer(Outcome::Error(Status::BAD_REQUEST));
            }
        }
        Action::StripPrefix(prefix) => {
            ex.req.strip_prefix(prefix);
        }
        Action::TryFiles(probe) => {
            if let Some(found) = probe_first(probe, ex, fx)
                && ex.req.rewrite(ex.arena.get(found)).is_err()
            {
                return Flow::Answer(Outcome::Error(Status::BAD_REQUEST));
            }
        }
        Action::ResponseHeaders(ops) => {
            for op in ops.iter() {
                let name = ex.arena.push(&op.name.name);
                let value = op.value.as_ref().map(|t| field_value(t, ex));
                ex.pending.ops.push(PendingOp {
                    name,
                    tag: op.name.tag,
                    value,
                });
            }
        }
        Action::RequestHeaders(ops) => request_headers(ops, ex),
        Action::Encode(set) => ex.pending.encode = *set,
        Action::Block(block) => return run_block(plan, block, ex, fx),
        Action::Answer(terminal) => return Flow::Answer(answer(terminal, ex)),
    }
    Flow::Next
}

fn request_headers(ops: &[HeaderOp], ex: &mut Exchange) {
    for op in ops {
        match &op.value {
            None => ex.req.fields.remove(&op.name),
            Some(t) => {
                let span = field_value(t, ex);
                ex.req.fields.set(&op.name, ex.arena.get(span));
            }
        }
    }
}

/// Expands a header value. A placeholder can carry a decoded CR, LF or NUL (`{query.k}`,
/// `{re.N}` of a decoded path), which a field value cannot hold: each becomes a space
/// (RFC 9110, section 5.5).
fn field_value(t: &crate::plan::Template, ex: &mut Exchange) -> ASpan {
    let span = t.expand(ex);
    let bad = |b: &u8| matches!(b, b'\r' | b'\n' | 0);
    if !ex.arena.get(span).iter().any(bad) {
        return span;
    }
    ex.arena.build(|out| {
        for i in span.start as usize..span.end as usize {
            let b = out[i];
            out.push(if bad(&b) { b' ' } else { b });
        }
    })
}

fn answer<'p>(terminal: &'p Terminal, ex: &mut Exchange) -> Outcome<'p> {
    match terminal {
        Terminal::Proxy(plan) => Outcome::Proxy(plan),
        Terminal::Files(plan) => Outcome::Files {
            plan,
            root: plan.root.expand(ex),
        },
        Terminal::Respond { status, body } => Outcome::Respond {
            status: status.or(ex.error.map(|e| e.status)).unwrap_or(Status::OK),
            body: body.expand(ex),
        },
        Terminal::Redirect { status, to } => Outcome::Redirect {
            status: *status,
            location: to.expand(ex),
        },
        Terminal::Error(status) => Outcome::Error(*status),
    }
}

#[cfg(test)]
mod tests {
    //! Golden routing tables (`tests/fixtures/routing/*.json`): each case is a request and what
    //! routing decides for it, written from the Caddy configs the fleet runs.

    use super::*;
    use crate::exchange::{ConnInfo, ErrorInfo, Proto, Scheme};
    use crate::plan::compile::{self, Sources};
    use crate::plan::{ListenerKey, ListenerKind, OriginAddr};
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// 2026-11-10T01:09:53Z, the portfolio build's reference time.
    const NOW: i64 = 1794272993;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Table {
        /// The config, relative to `tests/fixtures/routing`.
        config: String,
        /// The directory `@out@` stands for in the config, its includes and the expectations.
        #[serde(default)]
        out: Option<String>,
        /// Include path prefixes served from another directory (store paths in the emitted
        /// configs).
        #[serde(default)]
        sources: BTreeMap<String, String>,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Case {
        name: String,
        /// `METHOD scheme://host/target`; the scheme picks the listener.
        request: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
        /// `proxy <origin>[ timeouts]`, `files <root>`, `respond <status> <body>`,
        /// `redirect <status> <location>`, `error <status>`, or `none` (no site).
        outcome: String,
        /// The path after routing.
        #[serde(default)]
        path: Option<String>,
        /// The request-target that would go upstream.
        #[serde(default)]
        target: Option<String>,
        /// Vars after routing; `null` is unset. Vars not listed are not compared.
        #[serde(default)]
        vars: BTreeMap<String, Option<String>>,
        /// Every pending response header op, in order (names compared case-insensitively).
        #[serde(default)]
        ops: Option<Vec<(String, Option<String>)>>,
        #[serde(default)]
        encode: Option<Vec<String>>,
        /// Request header values after routing; `null` is absent.
        #[serde(default)]
        request_headers: BTreeMap<String, Option<String>>,
        /// The status the handler answers with (a missing file, an unreachable upstream).
        #[serde(default)]
        fail: Option<u16>,
        /// What the error routes answer for an error outcome or a `fail`: an outcome, or
        /// `bare` when no error route answers.
        #[serde(default)]
        then: Option<String>,
    }

    fn routing_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/routing")
    }

    struct Fixtures {
        replace: Vec<(String, String)>,
        prefixes: Vec<(String, PathBuf)>,
    }

    impl Fixtures {
        fn subst(&self, s: &str) -> String {
            self.replace
                .iter()
                .fold(s.to_owned(), |s, (from, to)| s.replace(from, to))
        }
    }

    impl Sources for Fixtures {
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            let p = path.to_string_lossy();
            let real = self
                .prefixes
                .iter()
                .find_map(|(prefix, dir)| {
                    p.strip_prefix(prefix.as_str())
                        .map(|r| dir.join(r.trim_start_matches('/')))
                })
                .unwrap_or_else(|| path.to_path_buf());
            let text = std::fs::read_to_string(real)?;
            Ok(self.subst(&text).into_bytes())
        }
    }

    fn load(table: &str) -> (Plan, Vec<Case>, Fixtures) {
        let dir = routing_dir();
        let text = std::fs::read_to_string(dir.join(table)).unwrap();
        let table: Table = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{table}: {e}"));
        let mut replace = vec![("@fixtures@".to_owned(), dir.display().to_string())];
        if let Some(out) = &table.out {
            replace.push(("@out@".to_owned(), dir.join(out).display().to_string()));
        }
        let fixtures = Fixtures {
            replace,
            prefixes: table
                .sources
                .iter()
                .map(|(prefix, to)| (prefix.clone(), dir.join(to)))
                .collect(),
        };
        let bytes = fixtures.read(&dir.join(&table.config)).unwrap();
        let config = crate::config::parse_config(&bytes).expect("the config fits the schema");
        let (plan, _) = compile::compile(&config, &fixtures, 1).unwrap_or_else(|d| {
            panic!(
                "{}: {:#?}",
                table.config,
                d.iter().map(ToString::to_string).collect::<Vec<_>>()
            )
        });
        (plan, table.cases, fixtures)
    }

    fn conn(scheme: Scheme) -> ConnInfo {
        let (port, kind) = match scheme {
            Scheme::Http => (80, ListenerKind::Http),
            Scheme::Https => (443, ListenerKind::Https),
        };
        ConnInfo {
            remote: "192.0.2.10:50000".parse().unwrap(),
            local_port: port,
            scheme,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
                kind,
            },
        }
    }

    /// Fills `ex` with the case's request as an h1 driver would.
    fn begin(ex: &mut Exchange, plan: &Plan, request: &str, headers: &[(String, String)]) {
        let (method, url) = request.split_once(' ').expect("METHOD url");
        let (scheme, rest) = url.split_once("://").expect("scheme://host/target");
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            other => panic!("scheme {other}"),
        };
        let slash = rest.find('/').unwrap_or(rest.len());
        let (authority, target) = rest.split_at(slash);
        ex.begin(conn(scheme), plan.var_count);
        ex.req
            .set_line(
                method.as_bytes(),
                target.as_bytes(),
                crate::msg::Version::Http11,
            )
            .expect("a valid target");
        ex.req.push_field(b"Host", authority.as_bytes());
        for (name, value) in headers {
            ex.req.push_field(name.as_bytes(), value.as_bytes());
        }
        ex.req.set_host(authority.as_bytes());
    }

    fn describe(plan: &Plan, outcome: &Outcome<'_>, ex: &Exchange) -> String {
        let text = |s: ASpan| String::from_utf8_lossy(ex.arena.get(s)).into_owned();
        match outcome {
            Outcome::Proxy(p) => {
                let u = &plan.upstreams[p.upstream.0 as usize];
                let scheme = if u.tls.is_some() { "https" } else { "http" };
                let host = match u.addr {
                    OriginAddr::Ip(addr) => addr.to_string(),
                    OriginAddr::Name => format!("{}:{}", u.host, u.port),
                };
                let mut s = format!("proxy {scheme}://{host}");
                if u.tls.as_ref().is_some_and(|t| !t.verify) {
                    s.push_str(" insecure");
                }
                if let Some(d) = p.response_header_timeout {
                    s.push_str(&format!(" responseHeader={}s", d.as_secs()));
                }
                if let Some(d) = p.tunnel_idle {
                    s.push_str(&format!(" tunnelIdle={}s", d.as_secs()));
                }
                s
            }
            Outcome::Files { root, .. } => format!("files {}", text(*root)),
            Outcome::Respond { status, body } => {
                format!("respond {} {}", status.code(), text(*body))
            }
            Outcome::Redirect { status, location } => {
                format!("redirect {} {}", status.code(), text(*location))
            }
            Outcome::Error(status) => format!("error {}", status.code()),
        }
    }

    fn effects<'a>(regex: &'a mut RegexCaches, catalog: &'a mut Catalog) -> Effects<'a> {
        Effects {
            regex,
            catalog,
            now: NOW,
        }
    }

    /// Routes one request as the pipeline does: the site's routes, then its error routes for
    /// an error outcome or a failing handler. Returns (outcome, error route outcome).
    fn route(
        plan: &Plan,
        ex: &mut Exchange,
        fx: &mut Effects<'_>,
        fail: Option<u16>,
    ) -> (String, Option<String>) {
        let Some((_, site)) = plan.site_for(&ex.conn.listener, ex.req.host()) else {
            return ("none".into(), None);
        };
        let outcome = run(plan, site, ex, fx);
        let first = describe(plan, &outcome, ex);
        let status = match outcome {
            Outcome::Error(status) => Some(status),
            _ => fail.map(|code| Status::new(code).unwrap()),
        };
        let then = status.map(|status| {
            ex.error = Some(ErrorInfo { status });
            match run_error(plan, site, ex, fx) {
                Some(o) => describe(plan, &o, ex),
                None => "bare".into(),
            }
        });
        (first, then)
    }

    fn check_table(table: &str) -> usize {
        let (plan, cases, fixtures) = load(table);
        let mut regex = RegexCaches::for_plan(&plan);
        let mut catalog = Catalog::default();
        let mut ex = Exchange::new(conn(Scheme::Https), plan.var_count);
        let mut failures = Vec::new();
        for case in &cases {
            let mut fx = effects(&mut regex, &mut catalog);
            begin(&mut ex, &plan, &case.request, &case.headers);
            let (outcome, then) = route(&plan, &mut ex, &mut fx, case.fail);
            let mut problems = Vec::new();
            let mut expect = |what: &str, want: String, got: String| {
                if want != got {
                    problems.push(format!("{what}: want {want:?}, got {got:?}"));
                }
            };
            expect("outcome", fixtures.subst(&case.outcome), outcome);
            if let Some(want) = &case.then {
                expect(
                    "then",
                    fixtures.subst(want),
                    then.clone().unwrap_or_default(),
                );
            }
            if let Some(want) = &case.path {
                let got = String::from_utf8_lossy(ex.req.path().as_bytes()).into_owned();
                expect("path", want.clone(), got);
            }
            if let Some(want) = &case.target {
                let mut out = Vec::new();
                ex.req.write_upstream_target(&mut out);
                expect(
                    "target",
                    want.clone(),
                    String::from_utf8_lossy(&out).into_owned(),
                );
            }
            for (name, want) in &case.vars {
                let got = plan
                    .var_names
                    .iter()
                    .position(|n| **n == **name)
                    .and_then(|i| ex.var(crate::plan::VarId(i as u16)))
                    .map(|v| String::from_utf8_lossy(v).into_owned());
                let want = want.as_ref().map(|w| fixtures.subst(w));
                expect(
                    &format!("vars.{name}"),
                    format!("{want:?}"),
                    format!("{got:?}"),
                );
            }
            if let Some(want) = &case.ops {
                let got: Vec<(String, Option<String>)> = ex
                    .pending
                    .ops
                    .iter()
                    .map(|op| {
                        (
                            String::from_utf8_lossy(ex.arena.get(op.name)).into_owned(),
                            op.value
                                .map(|v| String::from_utf8_lossy(ex.arena.get(v)).into_owned()),
                        )
                    })
                    .collect();
                let want: Vec<(String, Option<String>)> = want
                    .iter()
                    .map(|(n, v)| (n.to_ascii_lowercase(), v.clone()))
                    .collect();
                expect("ops", format!("{want:?}"), format!("{got:?}"));
            }
            if let Some(want) = &case.encode {
                let got: Vec<String> = ex
                    .pending
                    .encode
                    .iter()
                    .map(|e| String::from_utf8_lossy(e.token()).into_owned())
                    .collect();
                expect("encode", format!("{want:?}"), format!("{got:?}"));
            }
            for (name, want) in &case.request_headers {
                let header = HeaderName::new(name).unwrap();
                let got: Vec<String> = ex
                    .req
                    .fields
                    .values(&header)
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .collect();
                let got = (!got.is_empty()).then(|| got.join(", "));
                expect(
                    &format!("request header {name}"),
                    format!("{want:?}"),
                    format!("{got:?}"),
                );
            }
            if !problems.is_empty() {
                failures.push(format!("{}:\n    {}", case.name, problems.join("\n    ")));
            }
        }
        assert!(
            failures.is_empty(),
            "{table}: {} of {} cases fail:\n  {}",
            failures.len(),
            cases.len(),
            failures.join("\n  ")
        );
        cases.len()
    }

    #[test]
    fn portfolio() {
        assert!(check_table("portfolio.json") >= 60);
    }

    #[test]
    fn heimdall() {
        check_table("heimdall.json");
    }

    #[test]
    fn fleet_edge() {
        check_table("fleet-edge.json");
    }

    #[test]
    fn fleet_apps() {
        check_table("fleet-apps.json");
    }

    #[test]
    fn fleet_desktop() {
        check_table("fleet-desktop.json");
    }

    fn allocations() -> u64 {
        crate::runtime::testing::thread_allocations()
    }

    /// Requests of the portfolio table whose routing makes no file probe (the catalog's
    /// probe is the file server's, and allocates its path).
    const NO_PROBE: &[&str] = &[
        "GET https://example.org/blog/",
        "GET https://example.org/index.html?x=1",
        "GET https://example.org/_md/blog.md",
        "GET https://example.org/_astro/app.1a2b.css",
        "GET https://example.org/og/hello.png",
        "GET https://example.org/a%5Cb",
        "GET https://blog.example.org/blog/hello",
        "GET http://example.org/blog?x=1",
    ];

    /// What the pipeline asks of the router for one request, without describing the result.
    fn route_only(plan: &Plan, ex: &mut Exchange, fx: &mut Effects<'_>) {
        let Some((_, site)) = plan.site_for(&ex.conn.listener, ex.req.host()) else {
            return;
        };
        if let Outcome::Error(status) = run(plan, site, ex, fx) {
            ex.error = Some(ErrorInfo { status });
            run_error(plan, site, ex, fx);
        }
    }

    fn request_headers() -> Vec<(String, String)> {
        [
            ("Accept-Language", "pt-BR,pt;q=0.9"),
            ("Accept", "text/html, text/markdown, */*"),
            ("Cookie", "portfolio_lang=en; other=1"),
            ("User-Agent", "curl/8.5.0"),
            ("If-Modified-Since", "Tue, 10 Nov 2026 01:09:53 GMT"),
        ]
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .into()
    }

    #[test]
    fn routing_allocates_nothing_once_warm() {
        let (plan, _, _) = load("portfolio.json");
        let mut regex = RegexCaches::for_plan(&plan);
        let mut catalog = Catalog::default();
        let mut ex = Exchange::new(conn(Scheme::Https), plan.var_count);
        let headers = request_headers();
        let mut cold = 0;
        let mut warm = Vec::new();
        for round in 0..20 {
            for request in NO_PROBE {
                begin(&mut ex, &plan, request, &headers);
                let mut fx = effects(&mut regex, &mut catalog);
                let before = allocations();
                route_only(&plan, &mut ex, &mut fx);
                let n = allocations() - before;
                match round {
                    0 => cold += n,
                    10.. => warm.push((request, n)),
                    _ => {}
                }
            }
        }
        assert!(cold > 0, "the first round grows the exchange's buffers");
        let allocating: Vec<_> = warm.iter().filter(|(_, n)| *n > 0).collect();
        assert!(allocating.is_empty(), "{allocating:?}");
    }

    /// `cargo test --release -- --ignored --nocapture route_cost`: nanoseconds per routed
    /// request over the portfolio table's requests, with and without file probes.
    #[test]
    #[ignore = "a measurement; run in release on the benchmark host"]
    fn route_cost() {
        let (plan, cases, _) = load("portfolio.json");
        let mut regex = RegexCaches::for_plan(&plan);
        let mut catalog = Catalog::default();
        let mut ex = Exchange::new(conn(Scheme::Https), plan.var_count);
        let all: Vec<(String, Vec<(String, String)>)> = cases
            .iter()
            .map(|c| (c.request.clone(), c.headers.clone()))
            .collect();
        let headers = request_headers();
        let no_probe: Vec<(String, Vec<(String, String)>)> = NO_PROBE
            .iter()
            .map(|r| (r.to_string(), headers.clone()))
            .collect();
        for (label, set) in [("table", &all), ("no-probe", &no_probe)] {
            let mut probe_allocs = 0;
            for _ in 0..1000 {
                for (request, headers) in set {
                    begin(&mut ex, &plan, request, headers);
                    let mut fx = effects(&mut regex, &mut catalog);
                    route_only(&plan, &mut ex, &mut fx);
                }
            }
            let rounds = 20_000;
            let mut routed = std::time::Duration::ZERO;
            for _ in 0..rounds {
                for (request, headers) in set {
                    begin(&mut ex, &plan, request, headers);
                    let mut fx = effects(&mut regex, &mut catalog);
                    let before = allocations();
                    let start = std::time::Instant::now();
                    route_only(&plan, &mut ex, &mut fx);
                    routed += start.elapsed();
                    probe_allocs += allocations() - before;
                }
            }
            let n = rounds as u128 * set.len() as u128;
            println!(
                "{label}: {} requests, {} ns per routed request, {:.2} allocations per request",
                set.len(),
                routed.as_nanos() / n,
                probe_allocs as f64 / n as f64
            );
        }
    }
}
