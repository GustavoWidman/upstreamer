//! Config -> Plan. Runs on the control thread at startup and reload, and in `upstreamer check`
//! at Nix build time. Pure apart from reading `include` files through [`Sources`].
//!
//! Passes, in one walk per site:
//! 1. Splice includes (cycle check; fragment headers join site headers, fragment errors are
//!    appended).
//! 2. Intern var names to [`VarId`]s (a var read before any `set` can reach it is a warning:
//!    it expands to empty, like an unset Caddy var).
//! 3. Parse templates; resolve `{re.N}` against the step's own `when` (error if no regex there
//!    has N groups).
//! 4. Compile matchers to [`Cond`]; fold constants (e.g. `value` of a constant template) and
//!    order every `all` cheapest test first.
//! 5. Intern origins to [`OriginId`] by [`OriginKey`] (conflicting `idle` on one origin is an
//!    error), and balanced targets to [`PoolId`]s by value (`upstream.rs`).
//! 6. Validate header names (framing and hop-by-hop headers rejected), statuses, redirect
//!    codes.
//! 7. Flag unreachable steps after one that always answers (warning).
//! 8. Derive listeners and host indexes: each TLS site on its https addresses (+ QUIC if
//!    http3), each plain site on its http addresses, and one synthetic redirect site on the
//!    http addresses for every TLS site with redirectHttp. Duplicate host on one listener is
//!    an error.
//! 9. Label every terminal and `limit` step with a [`RouteSlot`] (`labels.rs`), kept only
//!    when some site serves `metrics`.
//!
//! Each feature's lowering lives in a child module: `upstream.rs` (proxy targets),
//! `limit.rs` (`limit` steps), `key.rs` (request keys), `labels.rs` (route slots, `metrics`,
//! `Observe`), `trust.rs` (`trustedProxies`), `acme.rs` (`tls.acme`).

mod acme;
mod key;
mod labels;
mod limit;
mod trust;
mod upstream;

use super::cond::{Glob, MethodSet, PathPatterns, Test};
use super::host::{HostIndex, HostPattern};
use super::template::{self, Captures, Part, Placeholder, Scope};
use super::{
    Action, Block, BlockKind, CertSource, Cond, Diagnostic, ErrorRoutePlan, FileProbe, FilesPlan,
    HeaderOp, LimitSpec, ListenerKey, ListenerKind, ListenerSpec, LogId, Observe, OriginAddr, Plan,
    ProxyPlan, RegexId, RouteLabel, RouteSlot, ServerParams, Severity, SiteId, SitePlan, Step,
    Template, Terminal, VarId,
};
use crate::config::{self, Config, Document, Format, OneOrMany};
use crate::encode::{Encoding, EncodingSet};
use crate::msg::{HeaderName, Status};
use regex_automata::meta::Regex;
use smallvec::SmallVec;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where include files come from. `run` reads the file system; tests use a map.
pub(crate) trait Sources {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>>;
}

/// Include files from the file system.
pub(crate) struct FileSystem;

impl Sources for FileSystem {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

const DEFAULT_DIAL: Duration = Duration::from_secs(5);
const DEFAULT_IDLE: Duration = Duration::from_secs(120);
/// Idle connections kept per origin and core. A core with more exchanges in flight than this
/// closes the surplus when they finish together and dials again for the next burst, so the
/// cap sits above the concurrency one core serves (an HTTP/2 client multiplexes up to
/// `max_streams` requests over each of its connections).
pub(crate) const MAX_IDLE_PER_CORE: u16 = 256;
const ALT_SVC_MAX_AGE: u32 = 86400;

/// Compiles a parsed config. `generation` is stamped into the plan. On error, every
/// diagnostic found is returned (not just the first), so one build shows all problems.
///
/// Diagnostics about the config itself have no `file`; the caller knows its path and
/// document (see [`super::load`]). Diagnostics inside an include name the include file and
/// are already located in it.
pub(crate) fn compile(
    config: &Config,
    sources: &dyn Sources,
    generation: u64,
) -> Result<(Plan, Vec<Diagnostic>), Vec<Diagnostic>> {
    let mut c = Compiler::new(sources);
    if let Some(spec) = &config.trusted_proxies {
        let at = Where {
            file: None,
            ptr: "/trustedProxies".to_owned(),
        };
        c.trust = c.trusted_proxies(spec, &at);
    }
    let mut sites: Vec<SitePlan> = Vec::new();
    for (i, site) in config.sites.iter().enumerate() {
        sites.push(c.site(site, &config.listen, &format!("/sites/{i}")));
    }
    let derived = c.listeners(config, &mut sites);
    c.observe(&mut sites);
    c.limits(&config.limits);
    c.locate_fragment_diagnostics();
    if c.diags.iter().any(Diagnostic::is_error) {
        return Err(c.diags);
    }
    let server = server_params(config);
    let upstream::Upstreams {
        origins,
        pools,
        sources,
    } = c.upstreams;
    let plan = Plan {
        generation,
        workers: config.workers,
        listeners: derived.listeners.into(),
        sites: sites.into(),
        origins: origins.into(),
        pools: pools.into(),
        sources: sources.into(),
        limits: c.limits.into(),
        routes: c.routes.into(),
        metrics: c.metrics,
        trust: c.trust,
        acme: c.acme.into(),
        regexes: c.regexes.into_iter().map(|(_, r)| r).collect(),
        var_count: c.vars.len() as u16,
        var_names: c.vars.into(),
        certs: derived.certs.into(),
        access_logs: c.access_logs.into(),
        server,
        user_sites: config.sites.len() as u16,
    };
    Ok((plan, c.diags))
}

fn server_params(config: &Config) -> ServerParams {
    let d = ServerParams::default();
    let t = &config.timeouts;
    let l = &config.limits;
    ServerParams {
        header_timeout: t.header.map_or(d.header_timeout, |x| x.0),
        keep_alive: t.keep_alive.map_or(d.keep_alive, |x| x.0),
        shutdown: t.shutdown.map_or(d.shutdown, |x| x.0),
        max_head_bytes: l.max_head_bytes.unwrap_or(d.max_head_bytes),
        max_header_fields: l.max_header_fields.unwrap_or(d.max_header_fields),
        max_streams: l.max_streams.unwrap_or(d.max_streams),
    }
}

struct Compiler<'s> {
    sources: &'s dyn Sources,
    diags: Vec<Diagnostic>,
    vars: Vec<Box<str>>,
    /// Interned by pattern.
    regexes: Vec<(String, Regex)>,
    /// Origins by identity, pools and discovery sources by value.
    upstreams: upstream::Upstreams,
    /// The include files being spliced, outermost first (cycle detection).
    includes: Vec<PathBuf>,
    /// Every fragment read, with its document when it parses, to locate diagnostics inside it.
    fragments: Vec<(PathBuf, Option<Document>)>,
    /// Interned by path.
    access_logs: Vec<PathBuf>,
    /// Limit tables, by `LimitId`.
    limits: Vec<LimitSpec>,
    /// Request series labels, by `RouteSlot`; slot 0 is ("", "").
    routes: Vec<RouteLabel>,
    /// A `metrics` step was compiled.
    metrics: bool,
    /// `trustedProxies`, compiled before the sites because proxy steps read it.
    trust: Option<crate::trust::TrustPlan>,
    /// One per site whose certificate comes from in-process ACME.
    acme: Vec<crate::acme::AcmePlan>,
    site: Site,
}

/// What the walk of one site accumulates.
#[derive(Default)]
struct Site {
    name: String,
    /// Header name -> where it was first set (for the duplicate check across fragments).
    headers: Vec<(HeaderName, Where)>,
    header_ops: Vec<HeaderOp>,
    /// Error routes contributed by included fragments, appended after the site's own.
    fragment_errors: Vec<ErrorRoutePlan>,
    /// Vars some earlier `set` assigns, in walk order.
    assigned: Vec<VarId>,
    /// Vars already reported as read before any `set`.
    warned: Vec<VarId>,
    /// Names of the steps enclosing the one being compiled, itself included: the nearest is
    /// a request's series label.
    named: Vec<Box<str>>,
    /// Enclosing steps (itself included) that have a `when`.
    guarded: u32,
    /// An address the site listens on that is not loopback, if any.
    exposed: Option<SocketAddr>,
}

/// A value's location: its file (`None`: the config) and JSON pointer.
#[derive(Clone, Debug)]
struct Where {
    file: Option<PathBuf>,
    ptr: String,
}

impl Where {
    fn at(&self, child: impl std::fmt::Display) -> Where {
        Where {
            file: self.file.clone(),
            ptr: format!("{}/{child}", self.ptr),
        }
    }
    /// A map key as a pointer segment (RFC 6901 escaping).
    fn key(&self, key: &str) -> Where {
        self.at(key.replace('~', "~0").replace('/', "~1"))
    }
}

#[derive(Clone, Copy)]
struct Ctx {
    in_error_route: bool,
}

/// A matcher after constant folding.
enum Folded {
    Always,
    Never,
    Cond(Cond),
}

impl<'s> Compiler<'s> {
    fn new(sources: &'s dyn Sources) -> Compiler<'s> {
        Compiler {
            sources,
            diags: Vec::new(),
            vars: Vec::new(),
            regexes: Vec::new(),
            upstreams: upstream::Upstreams::default(),
            includes: Vec::new(),
            fragments: Vec::new(),
            access_logs: Vec::new(),
            limits: Vec::new(),
            routes: vec![RouteLabel {
                site: "".into(),
                route: "".into(),
            }],
            metrics: false,
            trust: None,
            acme: Vec::new(),
            site: Site::default(),
        }
    }

    /// The head parser tokenises into a fixed table of field slots, so a larger limit could
    /// never be honoured.
    fn limits(&mut self, limits: &config::Limits) {
        const MAX_HEADER_FIELDS: u16 = 256;
        if let Some(n) = limits.max_header_fields.filter(|&n| n > MAX_HEADER_FIELDS) {
            let at = Where {
                file: None,
                ptr: "/limits/maxHeaderFields".to_owned(),
            };
            self.error(
                &at,
                format!(
                    "maxHeaderFields is {n}; the largest supported value is {MAX_HEADER_FIELDS}"
                ),
            );
        }
    }

    fn error(&mut self, at: &Where, message: impl Into<String>) {
        self.push(at, message.into(), Severity::Error);
    }

    fn warn(&mut self, at: &Where, message: impl Into<String>) {
        self.push(at, message.into(), Severity::Warning);
    }

    fn push(&mut self, at: &Where, message: String, severity: Severity) {
        let mut d = Diagnostic::error(at.file.as_deref(), at.ptr.clone(), message);
        d.severity = severity;
        if at.file.is_some() && !self.site.name.is_empty() {
            d.site = Some(self.site.name.clone());
        }
        self.diags.push(d);
    }

    fn locate_fragment_diagnostics(&mut self) {
        for (path, doc) in &self.fragments {
            let Some(doc) = doc else { continue };
            for d in self.diags.iter_mut() {
                if d.file.as_deref() == Some(path) && d.step.is_none() {
                    *d = d.clone().locate(doc);
                }
            }
        }
    }

    fn site(
        &mut self,
        site: &config::Site,
        listen: &config::ListenDefaults,
        ptr: &str,
    ) -> SitePlan {
        let addrs = match (&site.listen, &site.tls) {
            (Some(addrs), _) => addrs,
            (None, None) => &listen.http,
            (None, Some(_)) => &listen.https,
        };
        self.site = Site {
            name: site.name.clone(),
            exposed: addrs.iter().copied().find(|a| !a.ip().is_loopback()),
            ..Site::default()
        };
        let at = Where {
            file: None,
            ptr: ptr.to_owned(),
        };
        self.site_headers(&site.headers, &at.at("headers"));
        let ctx = Ctx {
            in_error_route: false,
        };
        let routes = self.block(&site.routes, BlockKind::Seq, ctx, &at.at("routes"));
        let mut errors = self.error_routes(&site.errors, &at.at("errors"));
        errors.append(&mut self.site.fragment_errors);
        let access_log = site
            .access_log
            .as_deref()
            .and_then(|path| self.access_log(path, &at.at("accessLog")));
        SitePlan {
            name: site.name.as_str().into(),
            headers: std::mem::take(&mut self.site.header_ops).into(),
            routes,
            errors: errors.into(),
            alt_svc: None,
            observe: access_log.map(|log| Observe {
                log: Some(log),
                metrics: false,
            }),
        }
    }

    /// The log a path names. A relative path is an error: it would depend on the directory
    /// the service happens to start in.
    fn access_log(&mut self, path: &Path, at: &Where) -> Option<LogId> {
        if !path.is_absolute() {
            self.error(
                at,
                format!("the access log path {} is not absolute", path.display()),
            );
            return None;
        }
        let index = match self.access_logs.iter().position(|p| p == path) {
            Some(index) => index,
            None => {
                self.access_logs.push(path.to_path_buf());
                self.access_logs.len() - 1
            }
        };
        Some(LogId(index as u16))
    }

    fn site_headers(&mut self, headers: &BTreeMap<String, Option<String>>, at: &Where) {
        let mut vars = std::mem::take(&mut self.vars);
        let mut scope = Scope {
            vars: &mut vars,
            captures: Captures::None,
            in_error_route: false,
            uses_captures: false,
            reads: Vec::new(),
        };
        let ops = self.header_ops(headers, at, &mut scope);
        self.vars = vars;
        for op in ops {
            let name_at = at.key(&String::from_utf8_lossy(&op.name.name));
            if let Some((_, first)) = self.site.headers.iter().find(|(n, _)| *n == op.name) {
                let first = describe(first);
                self.error(
                    &name_at,
                    format!("the site already sets this header ({first}); set it in one place"),
                );
                continue;
            }
            self.site.headers.push((op.name.clone(), name_at));
            self.site.header_ops.push(op);
        }
    }

    fn error_routes(&mut self, routes: &[config::ErrorRoute], at: &Where) -> Vec<ErrorRoutePlan> {
        let ctx = Ctx {
            in_error_route: true,
        };
        let mut out = Vec::new();
        for (i, route) in routes.iter().enumerate() {
            let at = at.at(i);
            let mut statuses = SmallVec::new();
            for (j, &code) in route.status.iter().flatten().enumerate() {
                match error_status(code) {
                    Some(s) => statuses.push(s),
                    None => self.error(
                        &at.at("status").at(j),
                        format!("{code} is not an error status (400 to 599)"),
                    ),
                }
            }
            let routes = self.block(&route.routes, BlockKind::Seq, ctx, &at.at("routes"));
            out.push(ErrorRoutePlan { statuses, routes });
        }
        out
    }

    fn block(&mut self, steps: &[config::Step], kind: BlockKind, ctx: Ctx, at: &Where) -> Block {
        let mut out: Vec<Step> = Vec::new();
        let mut ended: Option<String> = None;
        for (i, step) in steps.iter().enumerate() {
            let step_at = at.at(i);
            if let Some(by) = &ended {
                let by = by.clone();
                self.warn(
                    &step_at,
                    format!("unreachable: the step at {by} always answers before it"),
                );
            }
            let before = out.len();
            self.step(step, kind, ctx, &step_at, &mut out);
            let ends = out[before..].iter().any(|s| {
                s.when.is_none()
                    && match kind {
                        BlockKind::Seq => matches!(s.action, Action::Answer(..)),
                        BlockKind::First => true,
                    }
            });
            if ends && ended.is_none() {
                ended = Some(step_at.ptr.clone());
            }
        }
        Block {
            kind,
            steps: out.into(),
        }
    }

    fn step(
        &mut self,
        step: &config::Step,
        parent: BlockKind,
        ctx: Ctx,
        at: &Where,
        out: &mut Vec<Step>,
    ) {
        let mut vars = std::mem::take(&mut self.vars);
        let mut when_scope = Scope {
            vars: &mut vars,
            captures: Captures::None,
            in_error_route: ctx.in_error_route,
            uses_captures: false,
            reads: Vec::new(),
        };
        let mut sources: Vec<(RegexId, u8)> = Vec::new();
        let when = match &step.when {
            None => Folded::Always,
            Some(m) => self.matcher(m, &at.at("when"), &mut when_scope, Some(&mut sources)),
        };
        let mut reads = std::mem::take(&mut when_scope.reads);
        let named = step.name.as_deref().map(|n| self.site.named.push(n.into()));
        let guarded = step.when.is_some();
        self.site.guarded += u32::from(guarded);
        let mut scope = Scope {
            vars: &mut vars,
            captures: match &*sources {
                [] => Captures::None,
                [(_, groups)] => Captures::Groups(*groups),
                _ => Captures::Ambiguous,
            },
            in_error_route: ctx.in_error_route,
            uses_captures: false,
            reads: Vec::new(),
        };
        let action = self.action(&step.action, ctx, at, &mut scope);
        self.site.guarded -= u32::from(guarded);
        if named.is_some() {
            self.site.named.pop();
        }
        let uses_captures = scope.uses_captures;
        reads.append(&mut scope.reads);
        self.vars = vars;

        self.check_reads(&reads, at);
        if let Some(Action::Set(assigns)) = &action {
            self.site.assigned.extend(assigns.iter().map(|(id, _)| *id));
        }
        let mut when = match when {
            Folded::Never => {
                self.warn(
                    &at.at("when"),
                    "this `when` can never hold, so the step never runs",
                );
                return;
            }
            Folded::Always => None,
            Folded::Cond(c) => Some(c),
        };
        if uses_captures && let (Some(cond), [(regex, _)]) = (&mut when, &*sources) {
            mark_captures(cond, *regex);
        }
        let Some(action) = action else { return };
        match action {
            // An include without `when` in a sequence is its steps, in place.
            Action::Block(block)
                if when.is_none()
                    && parent == BlockKind::Seq
                    && block.kind == BlockKind::Seq
                    && matches!(step.action, config::Action::Include(_)) =>
            {
                out.extend(block.steps.into_vec());
            }
            action => out.push(Step {
                name: step.name.as_deref().map(Into::into),
                when,
                action,
            }),
        }
    }

    fn check_reads(&mut self, reads: &[VarId], at: &Where) {
        for &id in reads {
            if self.site.assigned.contains(&id) || self.site.warned.contains(&id) {
                continue;
            }
            self.site.warned.push(id);
            let name = self.vars[id.0 as usize].clone();
            self.warn(
                at,
                format!("`{{vars.{name}}}` is read before any `set` assigns it, so it expands to nothing"),
            );
        }
    }

    /// `None` when the action is invalid (its diagnostics are recorded).
    fn action(
        &mut self,
        action: &config::Action,
        ctx: Ctx,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<Action> {
        use config::Action as A;
        Some(match action {
            A::Set(assigns) => {
                let at = at.at("set");
                let mut out = Vec::new();
                for (name, value) in assigns {
                    if name.is_empty() {
                        self.error(&at.key(name), "a var needs a name");
                        continue;
                    }
                    let value = self.template(value, &at.key(name), scope)?;
                    out.push((template::intern(scope.vars, name), value));
                }
                Action::Set(out.into())
            }
            A::Rewrite(to) => {
                let at = at.at("rewrite");
                let t = self.template(to, &at, scope)?;
                if t.as_const().is_some_and(|c| !c.starts_with(b"/")) {
                    self.error(&at, "a rewrite target is a path starting with `/`");
                    return None;
                }
                Action::Rewrite(t)
            }
            A::StripPrefix(prefix) => {
                if !prefix.starts_with('/') || prefix.contains(['*', '?', '{']) {
                    self.error(
                        &at.at("stripPrefix"),
                        "a prefix is a literal path starting with `/`",
                    );
                    return None;
                }
                Action::StripPrefix(prefix.as_bytes().into())
            }
            A::TryFiles(spec) => Action::TryFiles(self.probe(spec, &at.at("tryFiles"), scope)?),
            A::Headers(ops) => {
                Action::ResponseHeaders(self.header_ops(ops, &at.at("headers"), scope).into())
            }
            A::RequestHeaders(ops) => {
                Action::RequestHeaders(self.header_ops(ops, &at.at("requestHeaders"), scope).into())
            }
            A::Encode(list) => {
                Action::Encode(EncodingSet::new(list.iter().map(|&e| Encoding::from(e))))
            }
            A::Routes(steps) => Action::Block(self.nested(scope, |c| {
                c.block(steps, BlockKind::Seq, ctx, &at.at("routes"))
            })),
            A::FirstOf(steps) => Action::Block(self.nested(scope, |c| {
                c.block(steps, BlockKind::First, ctx, &at.at("firstOf"))
            })),
            A::Include(path) => {
                Action::Block(self.nested(scope, |c| c.include(path, ctx, &at.at("include")))?)
            }
            A::Limit(spec) => {
                let route = self.route_slot();
                Action::Limit(self.limit(spec, route, ctx, &at.at("limit"), scope)?)
            }
            A::Proxy(spec) => {
                let proxy = self.proxy(spec, at, scope)?;
                Action::Answer(Terminal::Proxy(proxy), self.slot(ctx))
            }
            A::Files(spec) => {
                let files = self.files(spec, at, scope)?;
                Action::Answer(Terminal::Files(files), self.slot(ctx))
            }
            A::Respond(spec) => {
                let at = at.at("respond");
                let status = match spec.status {
                    None => None,
                    Some(code) => match Status::new(code).filter(|_| (200..=599).contains(&code)) {
                        Some(s) => Some(s),
                        None => {
                            self.error(
                                &at.at("status"),
                                format!("{code} is not a response status (200 to 599)"),
                            );
                            return None;
                        }
                    },
                };
                let body = match &spec.body {
                    Some(body) => self.template(body, &at.at("body"), scope)?,
                    None => Template::literal(b""),
                };
                Action::Answer(Terminal::Respond { status, body }, self.slot(ctx))
            }
            A::Redirect(spec) => {
                let at = at.at("redirect");
                let status = match spec.status {
                    301 | 302 | 303 | 307 | 308 => Status::new(spec.status)?,
                    code => {
                        self.error(
                            &at.at("status"),
                            format!("{code} is not a redirect status (301, 302, 303, 307, 308)"),
                        );
                        return None;
                    }
                };
                let to = self.template(&spec.to, &at.at("to"), scope)?;
                if to.as_const().is_some_and(|c| c.is_empty()) {
                    self.error(&at.at("to"), "a redirect needs a location");
                    return None;
                }
                Action::Answer(Terminal::Redirect { status, to }, self.slot(ctx))
            }
            A::Error(code) => match error_status(*code) {
                Some(s) => Action::Answer(Terminal::Error(s), self.slot(ctx)),
                None => {
                    self.error(
                        &at.at("error"),
                        format!("{code} is not an error status (400 to 599)"),
                    );
                    return None;
                }
            },
            A::Metrics(_) => {
                self.metrics(&at.at("metrics"));
                Action::Answer(Terminal::Metrics, self.slot(ctx))
            }
        })
    }

    /// Compiles nested steps. The step being compiled holds the var table in its scope; the
    /// nested steps intern into the same table.
    fn nested<R>(&mut self, scope: &mut Scope<'_>, f: impl FnOnce(&mut Self) -> R) -> R {
        std::mem::swap(scope.vars, &mut self.vars);
        let result = f(self);
        std::mem::swap(scope.vars, &mut self.vars);
        result
    }

    fn template(&mut self, src: &str, at: &Where, scope: &mut Scope<'_>) -> Option<Template> {
        match Template::parse(src, scope) {
            Ok(t) => Some(t),
            Err(e) => {
                let message = if src.len() > 1 {
                    format!("{} (at byte {} of {src:?})", e.message, e.offset)
                } else {
                    e.message
                };
                self.error(at, message);
                None
            }
        }
    }

    fn probe(
        &mut self,
        spec: &config::FileProbeSpec,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<FileProbe> {
        let root = self.root(&spec.root, &at.at("root"), scope)?;
        if spec.paths.is_empty() {
            self.error(&at.at("paths"), "list at least one path to try");
            return None;
        }
        let mut paths = Vec::new();
        for (i, p) in spec.paths.iter().enumerate() {
            paths.push(self.template(p, &at.at("paths").at(i), scope)?);
        }
        Some(FileProbe {
            root,
            paths: paths.into(),
        })
    }

    fn root(&mut self, src: &str, at: &Where, scope: &mut Scope<'_>) -> Option<Template> {
        let t = self.template(src, at, scope)?;
        if t.as_const().is_some_and(|c| !c.starts_with(b"/")) {
            self.warn(
                at,
                "a root is an absolute directory; this one never finds a file",
            );
        }
        Some(t)
    }

    fn header_ops(
        &mut self,
        ops: &BTreeMap<String, Option<String>>,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Vec<HeaderOp> {
        let mut out = Vec::new();
        for (name, value) in ops {
            let at = at.key(name);
            let Some(header) = HeaderName::new(name) else {
                self.error(&at, format!("{name:?} is not a header field name"));
                continue;
            };
            if header.tag.framing() || header.tag.hop_by_hop() {
                self.error(
                    &at,
                    format!("`{name}` is a framing or hop-by-hop header, which only the protocol layer writes"),
                );
                continue;
            }
            let value = match value {
                None => None,
                Some(v) => {
                    if v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                        self.error(&at, "a header value cannot hold CR, LF or NUL");
                        continue;
                    }
                    match self.template(v, &at, scope) {
                        Some(t) => Some(t),
                        None => continue,
                    }
                }
            };
            out.push(HeaderOp {
                name: header,
                value,
            });
        }
        out
    }

    fn include(&mut self, path: &Path, ctx: Ctx, at: &Where) -> Option<Block> {
        if !path.is_absolute() {
            self.error(at, "an include names an absolute path (a store path)");
            return None;
        }
        if let Some(i) = self.includes.iter().position(|p| p == path) {
            let cycle: Vec<String> = self.includes[i..]
                .iter()
                .chain([&path.to_path_buf()])
                .map(|p| p.display().to_string())
                .collect();
            self.error(at, format!("include cycle: {}", cycle.join(" -> ")));
            return None;
        }
        let bytes = match self.sources.read(path) {
            Ok(b) => b,
            Err(e) => {
                self.error(at, format!("cannot read {}: {e}", path.display()));
                return None;
            }
        };
        let file = Where {
            file: Some(path.to_path_buf()),
            ptr: String::new(),
        };
        let format = Format::of(path);
        let fragment = match config::parse_fragment(format, &bytes) {
            Ok(config::Parsed { value, doc }) => {
                self.fragments.push((path.to_path_buf(), Some(doc)));
                value
            }
            Err(e) => {
                let doc = config::document(format, &bytes);
                self.fragments.push((path.to_path_buf(), doc));
                let mut message = e.message;
                if e.line > 0 {
                    message.push_str(&format!(" (line {}, column {})", e.line, e.column));
                }
                self.error(
                    &Where {
                        ptr: e.pointer,
                        ..file
                    },
                    message,
                );
                return None;
            }
        };
        if fragment.fragment != 1 {
            self.error(
                &file.at("fragment"),
                format!(
                    "unsupported fragment version {}; this upstreamer reads version 1",
                    fragment.fragment
                ),
            );
            return None;
        }
        self.includes.push(path.to_path_buf());
        self.site_headers(&fragment.headers, &file.at("headers"));
        let block = self.block(&fragment.routes, BlockKind::Seq, ctx, &file.at("routes"));
        let mut errors = self.error_routes(&fragment.errors, &file.at("errors"));
        self.site.fragment_errors.append(&mut errors);
        self.includes.pop();
        Some(block)
    }

    fn proxy(
        &mut self,
        spec: &config::ProxySpec,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<ProxyPlan> {
        let at = at.at("proxy");
        let default_timeouts = config::ProxyTimeouts::default();
        let no_headers = BTreeMap::new();
        let (headers, timeouts) = match spec {
            config::ProxySpec::To(_) => (&no_headers, &default_timeouts),
            config::ProxySpec::Full(full) => (&full.headers, &full.timeouts),
        };
        let idle = timeouts.idle.map_or(DEFAULT_IDLE, |d| d.0);
        let to = self.target(spec, idle, &at, scope)?;
        let mut ops: Vec<HeaderOp> = Vec::new();
        let forwarded_for = match self.trust {
            Some(_) => Placeholder::ForwardedFor,
            None => Placeholder::RemoteHost,
        };
        for (name, ph) in [
            ("x-forwarded-for", forwarded_for),
            ("x-forwarded-proto", Placeholder::Scheme),
            ("x-forwarded-host", Placeholder::Host),
        ] {
            if !headers.keys().any(|k| k.eq_ignore_ascii_case(name)) {
                ops.push(HeaderOp {
                    name: HeaderName::new(name)?,
                    value: Some(Template::from_parts(vec![Part::Ph(ph)])),
                });
            }
        }
        ops.extend(self.header_ops(headers, &at.at("headers"), scope));
        Some(ProxyPlan {
            to,
            headers: ops.into(),
            dial_timeout: timeouts.dial.map_or(DEFAULT_DIAL, |d| d.0),
            response_header_timeout: timeouts.response_header.map(|d| d.0),
            tunnel_idle: timeouts.tunnel_idle.map(|d| d.0),
        })
    }

    fn files(
        &mut self,
        spec: &config::FilesSpec,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<FilesPlan> {
        let at = at.at("files");
        let root = self.root(&spec.root, &at.at("root"), scope)?;
        let mut precompressed: SmallVec<[Encoding; 3]> = SmallVec::new();
        for &e in &spec.precompressed {
            let e = Encoding::from(e);
            if !precompressed.contains(&e) {
                precompressed.push(e);
            }
        }
        let etag_sidecar = match &spec.etag_sidecar {
            None => None,
            Some(ext) if ext.len() > 1 && ext.starts_with('.') && !ext.contains('/') => {
                Some(ext.as_bytes().into())
            }
            Some(_) => {
                self.error(
                    &at.at("etagSidecar"),
                    "an ETag sidecar is a file extension such as `.etag`",
                );
                return None;
            }
        };
        let index: Box<[Box<[u8]>]> = match &spec.index {
            None => [Box::from(&b"index.html"[..])].into(),
            Some(names) => {
                for (i, name) in names.iter().enumerate() {
                    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                        self.error(
                            &at.at("index").at(i),
                            "an index is a file name, without `/`",
                        );
                        return None;
                    }
                }
                names.iter().map(|n| n.as_bytes().into()).collect()
            }
        };
        Some(FilesPlan {
            root,
            precompressed,
            etag_sidecar,
            index,
        })
    }

    /// Compiles a matcher. `sources` collects the regexes `{re.N}` may read: the step's
    /// top-level `pathRegex` and `regex` (`None` inside `all`/`any`/`none`).
    fn matcher(
        &mut self,
        m: &config::Matcher,
        at: &Where,
        scope: &mut Scope<'_>,
        mut sources: Option<&mut Vec<(RegexId, u8)>>,
    ) -> Folded {
        let mut parts: Vec<Folded> = Vec::new();
        let mut test = |t: Test| parts.push(Folded::Cond(Cond::Test(t)));

        if let Some(path) = &m.path {
            match path_patterns(path.as_slice()) {
                Ok(Some(p)) => test(Test::Path(p)),
                Ok(None) => {}
                Err((i, message)) => {
                    let at = match path {
                        OneOrMany::One(_) => at.at("path"),
                        OneOrMany::Many(_) => at.at("path").at(i),
                    };
                    self.error(&at, message);
                }
            }
        }
        if let Some(src) = &m.path_regex
            && let Some((regex, groups)) = self.regex(src, &at.at("pathRegex"))
        {
            if let Some(s) = sources.as_deref_mut() {
                s.push((regex, groups));
            }
            test(Test::PathRegex {
                regex,
                captures: false,
            });
        }
        if let Some(methods) = &m.method {
            let mut set = MethodSet::default();
            for (i, token) in methods.as_slice().iter().enumerate() {
                if token.is_empty() || !token.bytes().all(is_tchar) {
                    let at = match methods {
                        OneOrMany::One(_) => at.at("method"),
                        OneOrMany::Many(_) => at.at("method").at(i),
                    };
                    self.error(&at, format!("{token:?} is not a method"));
                }
                set.insert(token.as_bytes());
            }
            test(Test::Method(set));
        }
        for (name, globs) in m.header.iter().flatten() {
            let Some(header) = HeaderName::new(name) else {
                self.error(&at.at("header").key(name), "not a header field name");
                continue;
            };
            test(Test::Header {
                name: header,
                globs: globs
                    .as_slice()
                    .iter()
                    .map(|g| Glob::new(g.as_bytes()))
                    .collect(),
            });
        }
        for (name, src) in m.header_regex.iter().flatten() {
            let at = at.at("headerRegex").key(name);
            let Some(header) = HeaderName::new(name) else {
                self.error(&at, "not a header field name");
                continue;
            };
            if let Some((regex, _)) = self.regex(src, &at) {
                test(Test::HeaderRegex {
                    name: header,
                    regex,
                });
            }
        }
        for (key, values) in m.query.iter().flatten() {
            test(Test::Query {
                key: key.as_bytes().into(),
                values: values
                    .as_slice()
                    .iter()
                    .map(|v| v.as_bytes().into())
                    .collect(),
            });
        }
        match (&m.value, &m.in_, &m.regex) {
            (None, None, None) => {}
            (Some(value), Some(set), None) => {
                if let Some(value) = self.template(value, &at.at("value"), scope) {
                    let set: Box<[Box<[u8]>]> = set.iter().map(|s| s.as_bytes().into()).collect();
                    match value.as_const() {
                        Some(c) if set.iter().any(|s| **s == *c) => parts.push(Folded::Always),
                        Some(_) => parts.push(Folded::Never),
                        None => parts.push(Folded::Cond(Cond::Test(Test::ValueIn { value, set }))),
                    }
                }
            }
            (Some(value), None, Some(src)) => {
                let value = self.template(value, &at.at("value"), scope);
                let regex = self.regex(src, &at.at("regex"));
                if let (Some(value), Some((regex, groups))) = (value, regex) {
                    if let Some(s) = sources {
                        s.push((regex, groups));
                    }
                    parts.push(Folded::Cond(Cond::Test(Test::ValueRegex {
                        value,
                        regex,
                        captures: false,
                    })));
                }
            }
            (Some(_), _, _) => self.error(
                &at.at("value"),
                "`value` is compared with exactly one of `in` or `regex`",
            ),
            (None, _, _) => {
                let key = if m.in_.is_some() { "in" } else { "regex" };
                self.error(&at.at(key), format!("`{key}` compares a `value`; add one"));
            }
        }
        if let Some(spec) = &m.file
            && let Some(probe) = self.probe(spec, &at.at("file"), scope)
        {
            parts.push(Folded::Cond(Cond::Test(Test::File(probe))));
        }
        if let Some(after) = m.after {
            parts.push(Folded::Cond(Cond::Test(Test::After(after.0))));
        }
        for (key, list) in [("all", &m.all), ("any", &m.any), ("none", &m.none)] {
            let Some(list) = list else { continue };
            let items: Vec<Folded> = list
                .iter()
                .enumerate()
                .map(|(i, m)| self.matcher(m, &at.at(key).at(i), scope, None))
                .collect();
            parts.push(match key {
                "all" => fold_all(items),
                "any" => fold_any(items),
                _ => fold_none(items),
            });
        }
        fold_all(parts)
    }

    /// Interns a regex by pattern. Returns its id and group count (group 0 included).
    fn regex(&mut self, src: &str, at: &Where) -> Option<(RegexId, u8)> {
        let index = match self.regexes.iter().position(|(p, _)| p == src) {
            Some(i) => i,
            None => match Regex::new(src) {
                Ok(r) => {
                    self.regexes.push((src.to_owned(), r));
                    self.regexes.len() - 1
                }
                Err(e) => {
                    self.error(at, format!("invalid regex: {e}"));
                    return None;
                }
            },
        };
        let groups = self.regexes[index].1.captures_len();
        Some((RegexId(index as u16), groups.min(u8::MAX as usize) as u8))
    }

    fn listeners(&mut self, config: &Config, sites: &mut Vec<SitePlan>) -> Derived {
        let mut listeners: Vec<(ListenerKey, Vec<HostEntry>)> = Vec::new();
        let mut certs: Vec<CertSource> = Vec::new();
        let mut redirect_hosts: Vec<HostEntry> = Vec::new();
        let https_port = config.listen.https.first().map_or(443, SocketAddr::port);

        for (i, site) in config.sites.iter().enumerate() {
            let id = SiteId(i as u16);
            let at = Where {
                file: None,
                ptr: format!("/sites/{i}"),
            };
            if site.hosts.is_empty() {
                self.error(
                    &at.at("hosts"),
                    "a site needs at least one host (`*` for any)",
                );
            }
            let mut patterns = Vec::new();
            for (j, name) in site.hosts.iter().enumerate() {
                match HostPattern::parse(name) {
                    Some(p) => patterns.push(HostEntry {
                        pattern: p,
                        site: id,
                        at: at.at("hosts").at(j),
                        redirect_of: None,
                    }),
                    None => self.error(
                        &at.at("hosts").at(j),
                        format!("{name:?} is not a host name, `*.suffix` or `*`"),
                    ),
                }
            }
            match &site.tls {
                None => {
                    for &addr in site.listen.as_deref().unwrap_or(&config.listen.http) {
                        add(&mut listeners, addr, ListenerKind::Http, &patterns);
                    }
                }
                Some(tls) => {
                    let addrs = site.listen.as_deref().unwrap_or(&config.listen.https);
                    let http3 = tls.http3.unwrap_or(config.http3);
                    for &addr in addrs {
                        add(&mut listeners, addr, ListenerKind::Https, &patterns);
                        if http3 {
                            add(&mut listeners, addr, ListenerKind::Quic, &patterns);
                        }
                    }
                    if http3 && let Some(addr) = addrs.first() {
                        sites[i].alt_svc = Some(
                            format!("h3=\":{}\"; ma={ALT_SVC_MAX_AGE}", addr.port())
                                .into_bytes()
                                .into(),
                        );
                    }
                    if tls.redirect_http && site.listen.is_none() {
                        redirect_hosts.extend(patterns.iter().map(|e| HostEntry {
                            redirect_of: Some(id),
                            ..e.clone()
                        }));
                    }
                    let names: Vec<Box<str>> = site
                        .hosts
                        .iter()
                        .map(|h| h.to_ascii_lowercase().into())
                        .collect();
                    let tls_at = at.at("tls");
                    let source = match (&tls.cert, &tls.key, &tls.acme) {
                        (Some(cert), Some(key), None) => Some(CertSource {
                            cert: cert.clone(),
                            key: key.clone(),
                            names: names.into(),
                        }),
                        (None, None, Some(acme)) => self.acme_certificate(
                            &site.name,
                            names,
                            acme,
                            config.acme.as_ref(),
                            tls,
                            &tls_at.at("acme"),
                        ),
                        (_, _, Some(_)) => {
                            self.error(
                                &tls_at,
                                "a TLS site takes `cert` and `key`, or `acme`, not both",
                            );
                            None
                        }
                        (_, _, None) => {
                            self.error(
                                &tls_at,
                                "a TLS site needs `cert` and `key` files, or `acme`",
                            );
                            None
                        }
                    };
                    if let Some(source) = source {
                        add_cert(&mut certs, source);
                    }
                }
            }
        }

        if !redirect_hosts.is_empty() {
            let id = SiteId(sites.len() as u16);
            for e in &mut redirect_hosts {
                e.site = id;
            }
            let acme_http01 = self.acme.iter().any(crate::acme::AcmePlan::answers_http01);
            let site = redirect_site(https_port, acme_http01, self.redirect_slots());
            sites.push(site);
            for &addr in &config.listen.http {
                add(&mut listeners, addr, ListenerKind::Http, &redirect_hosts);
            }
        }

        let name = |e: &HostEntry| {
            let site = &config.sites[e.redirect_of.unwrap_or(e.site).0 as usize].name;
            match e.redirect_of {
                Some(_) => format!("the HTTP->HTTPS redirect of site `{site}`"),
                None => format!("site `{site}`"),
            }
        };
        let mut specs = Vec::new();
        // One report per duplicated host entry, at its first listener.
        let mut reported: Vec<String> = Vec::new();
        for (key, entries) in listeners {
            let mut unique: Vec<&HostEntry> = Vec::new();
            for e in &entries {
                let Some(first) = unique.iter().find(|u| u.pattern == e.pattern) else {
                    unique.push(e);
                    continue;
                };
                if reported.contains(&e.at.ptr) {
                    continue;
                }
                reported.push(e.at.ptr.clone());
                let message = format!(
                    "host `{}` on {} {} is served by both {} and {}",
                    e.pattern,
                    kind_name(key.kind),
                    key.addr,
                    name(first),
                    name(e),
                );
                self.error(&e.at, message);
            }
            let hosts = HostIndex::new(unique.iter().map(|e| (e.pattern.clone(), e.site)));
            specs.push(ListenerSpec { key, hosts });
        }
        Derived {
            listeners: specs,
            certs,
        }
    }
}

/// Adds a certificate source, merging its names into an earlier one with the same files.
fn add_cert(certs: &mut Vec<CertSource>, source: CertSource) {
    match certs
        .iter_mut()
        .find(|c| c.cert == source.cert && c.key == source.key)
    {
        Some(c) => {
            let mut all = std::mem::take(&mut c.names).into_vec();
            for name in source.names {
                if !all.contains(&name) {
                    all.push(name);
                }
            }
            c.names = all.into();
        }
        None => certs.push(source),
    }
}

/// Puts `entries` on the listener for `addr` and `kind`, creating it on first use.
fn add(
    listeners: &mut Vec<(ListenerKey, Vec<HostEntry>)>,
    addr: SocketAddr,
    kind: ListenerKind,
    entries: &[HostEntry],
) {
    let key = ListenerKey { addr, kind };
    match listeners.iter_mut().find(|(k, _)| *k == key) {
        Some((_, list)) => list.extend_from_slice(entries),
        None => listeners.push((key, entries.to_vec())),
    }
}

struct Derived {
    listeners: Vec<ListenerSpec>,
    certs: Vec<CertSource>,
}

#[derive(Clone, Debug)]
struct HostEntry {
    pattern: HostPattern,
    site: SiteId,
    at: Where,
    /// Set for the redirect site's entries: the TLS site they redirect for.
    redirect_of: Option<SiteId>,
}

pub(crate) fn kind_name(kind: ListenerKind) -> &'static str {
    match kind {
        ListenerKind::Http => "http",
        ListenerKind::Https => "https",
        ListenerKind::Quic => "quic",
    }
}

/// Where an ACME CA fetches HTTP-01 tokens (RFC 8555 section 8.3).
const ACME_CHALLENGE_PREFIX: &[u8] = b"/.well-known/acme-challenge/";

/// The site every TLS site's names reach on the http addresses: `308` to the same host and
/// target on https, after answering ACME HTTP-01 tokens when in-process ACME uses them.
/// `slots` labels its two steps (the redirect, the token).
fn redirect_site(https_port: u16, acme_http01: bool, slots: [Option<RouteSlot>; 2]) -> SitePlan {
    let mut parts = vec![
        Part::Lit((*b"https://").into()),
        Part::Ph(Placeholder::Host),
    ];
    if https_port != 443 {
        parts.push(Part::Lit(format!(":{https_port}").into_bytes().into()));
    }
    parts.push(Part::Ph(Placeholder::Uri));
    let mut steps = Vec::new();
    if acme_http01 {
        steps.push(Step {
            name: Some("acme_challenge".into()),
            when: Some(Cond::Test(Test::Path(PathPatterns {
                exact: Box::new([]),
                prefix: Box::new([ACME_CHALLENGE_PREFIX.into()]),
                suffix: Box::new([]),
                glob: Box::new([]),
            }))),
            action: Action::Answer(Terminal::AcmeChallenge, slots[1]),
        });
    }
    steps.push(Step {
        name: Some("redirect_http".into()),
        when: None,
        action: Action::Answer(
            Terminal::Redirect {
                status: Status::PERMANENT_REDIRECT,
                to: Template::from_parts(parts),
            },
            slots[0],
        ),
    });
    SitePlan {
        name: REDIRECT_SITE.into(),
        headers: Box::new([]),
        routes: Block {
            kind: BlockKind::Seq,
            steps: steps.into(),
        },
        errors: Box::new([]),
        alt_svc: None,
        observe: None,
    }
}

/// The name of the synthetic HTTP->HTTPS redirect site, in logs and metrics labels.
const REDIRECT_SITE: &str = "HTTP->HTTPS redirect";

fn mark_captures(cond: &mut Cond, regex: RegexId) {
    match cond {
        Cond::Test(Test::PathRegex { regex: r, captures })
        | Cond::Test(Test::ValueRegex {
            regex: r, captures, ..
        }) if *r == regex => *captures = true,
        Cond::All(items) => items.iter_mut().for_each(|c| mark_captures(c, regex)),
        _ => {}
    }
}

fn fold_all(items: Vec<Folded>) -> Folded {
    let mut conds = Vec::new();
    for item in items {
        match item {
            Folded::Never => return Folded::Never,
            Folded::Always => {}
            Folded::Cond(Cond::All(inner)) => conds.extend(inner.into_vec()),
            Folded::Cond(c) => conds.push(c),
        }
    }
    conds.sort_by_key(Cond::cost);
    match conds.len() {
        0 => Folded::Always,
        1 => Folded::Cond(conds.pop().expect("one condition")),
        _ => Folded::Cond(Cond::All(conds.into())),
    }
}

fn fold_any(items: Vec<Folded>) -> Folded {
    let mut conds = Vec::new();
    for item in items {
        match item {
            Folded::Always => return Folded::Always,
            Folded::Never => {}
            Folded::Cond(c) => conds.push(c),
        }
    }
    conds.sort_by_key(Cond::cost);
    match conds.len() {
        0 => Folded::Never,
        1 => Folded::Cond(conds.pop().expect("one condition")),
        _ => Folded::Cond(Cond::Any(conds.into())),
    }
}

fn fold_none(items: Vec<Folded>) -> Folded {
    match fold_any(items) {
        Folded::Always => Folded::Never,
        Folded::Never => Folded::Always,
        Folded::Cond(Cond::Any(conds)) => Folded::Cond(Cond::None(conds)),
        Folded::Cond(c) => Folded::Cond(Cond::None(Box::new([c]))),
    }
}

/// Splits path patterns by shape. `Ok(None)`: a `*` pattern matches every path.
fn path_patterns(patterns: &[String]) -> Result<Option<PathPatterns>, (usize, String)> {
    let mut exact = Vec::new();
    let mut prefix = Vec::new();
    let mut suffix = Vec::new();
    let mut glob = Vec::new();
    for (i, p) in patterns.iter().enumerate() {
        let b = p.as_bytes();
        if !(p.starts_with('/') || p.starts_with('*')) {
            return Err((i, format!("{p:?}: a path pattern starts with `/` or `*`")));
        }
        let stars = b.iter().filter(|&&c| c == b'*').count();
        match stars {
            0 => exact.push(b.into()),
            1 if b == b"*" => return Ok(None),
            1 if b.ends_with(b"*") => prefix.push(b[..b.len() - 1].into()),
            1 if b.starts_with(b"*") => suffix.push(b[1..].into()),
            _ => glob.push(Glob::new(b)),
        }
    }
    Ok(Some(PathPatterns {
        exact: exact.into(),
        prefix: prefix.into(),
        suffix: suffix.into(),
        glob: glob.into(),
    }))
}

struct Origin {
    https: bool,
    host: Box<str>,
    port: u16,
    addr: OriginAddr,
}

/// `http://host:port` or `https://host:port`; the port defaults to the scheme's.
fn parse_origin(to: &str) -> Result<Origin, String> {
    let bad = |why: &str| format!("upstream {to:?}: {why}");
    let (https, rest) = match to.split_once("://") {
        Some((s, rest)) if s.eq_ignore_ascii_case("http") => (false, rest),
        Some((s, rest)) if s.eq_ignore_ascii_case("https") => (true, rest),
        _ => return Err(bad("write it as http://host:port or https://host:port")),
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#']) {
        return Err(bad(
            "an upstream has no path; use `rewrite` or `stripPrefix`",
        ));
    }
    if authority.contains('@') {
        return Err(bad("an upstream has no user info"));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| bad("unclosed `[`"))?;
        (h, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => {
            if https {
                443
            } else {
                80
            }
        }
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| bad("not a port"))?,
    };
    if host.is_empty() {
        return Err(bad("no host"));
    }
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => OriginAddr::Ip(SocketAddr::new(ip, port)),
        Err(_) if authority.starts_with('[') => return Err(bad("not an IPv6 address")),
        Err(_) => {
            if !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
            {
                return Err(bad("not a host name"));
            }
            OriginAddr::Name
        }
    };
    Ok(Origin {
        https,
        host: host.to_ascii_lowercase().into(),
        port,
        addr,
    })
}

fn error_status(code: u16) -> Option<Status> {
    Status::new(code).filter(|_| (400..=599).contains(&code))
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn fmt_duration(d: Duration) -> String {
    let ms = d.as_millis();
    match ms {
        _ if ms.is_multiple_of(3_600_000) => format!("{}h", ms / 3_600_000),
        _ if ms.is_multiple_of(60_000) => format!("{}m", ms / 60_000),
        _ if ms.is_multiple_of(1000) => format!("{}s", ms / 1000),
        _ => format!("{ms}ms"),
    }
}

fn describe(w: &Where) -> String {
    match &w.file {
        Some(f) => format!("{}:{}", f.display(), w.ptr),
        None => w.ptr.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{KeyPlan, OriginId, Target};
    use std::collections::HashMap;

    struct Files(HashMap<PathBuf, String>);

    impl Sources for Files {
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            self.0
                .get(path)
                .map(|s| s.clone().into_bytes())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    fn compile_json(
        json: &str,
        files: &[(&str, &str)],
    ) -> Result<(Plan, Vec<Diagnostic>), Vec<Diagnostic>> {
        let config = config::parse_config(Format::Json, json.as_bytes())
            .expect("schema")
            .value;
        let files = Files(
            files
                .iter()
                .map(|(p, s)| (PathBuf::from(p), s.to_string()))
                .collect(),
        );
        compile(&config, &files, 1)
    }

    fn errors(json: &str, files: &[(&str, &str)]) -> Vec<String> {
        compile_json(json, files)
            .expect_err("an invalid config")
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn site(routes: &str) -> String {
        format!(
            r#"{{"version":1,"sites":[{{"name":"a","hosts":["a.example"],"routes":{routes}}}]}}"#
        )
    }

    #[test]
    fn header_field_limit_is_capped_at_the_parser_table() {
        let config =
            |n: u32| format!(r#"{{"version":1,"limits":{{"maxHeaderFields":{n}}},"sites":[]}}"#);
        let (plan, _) = compile_json(&config(256), &[]).expect("256 fields fit the parser");
        assert_eq!(plan.server.max_header_fields, 256);
        assert_eq!(
            errors(&config(257), &[]),
            ["/limits/maxHeaderFields: maxHeaderFields is 257; the largest supported value is 256"]
        );
    }

    #[test]
    fn origins() {
        let o = parse_origin("http://127.0.0.1:7979").unwrap();
        assert!(!o.https);
        assert!(matches!(o.addr, OriginAddr::Ip(a) if a == "127.0.0.1:7979".parse().unwrap()));
        let o = parse_origin("https://[::1]").unwrap();
        assert_eq!(o.port, 443);
        assert!(matches!(o.addr, OriginAddr::Ip(a) if a == "[::1]:443".parse().unwrap()));
        let o = parse_origin("http://Storage:9000/").unwrap();
        assert_eq!(&*o.host, "storage");
        assert!(matches!(o.addr, OriginAddr::Name));
        for bad in [
            "127.0.0.1:80",
            "ftp://a",
            "http://a:0",
            "http://a/x",
            "http://u@a",
            "http://:80",
            "http://[zz]:1",
        ] {
            assert!(parse_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn constant_matchers_fold() {
        let (plan, warnings) = compile_json(
            &site(
                r#"[
                {"when":{"value":"x","in":["x"]},"set":{"a":"1"}},
                {"when":{"path":"*","method":"GET"},"set":{"b":"1"}},
                {"when":{"value":"x","in":["y"]},"set":{"c":"1"}},
                {"when":{"none":[{"path":"*"}]},"set":{"d":"1"}},
                {"error":404}
            ]"#,
            ),
            &[],
        )
        .unwrap();
        let steps = &plan.sites[0].routes.steps;
        assert_eq!(steps.len(), 3, "the two never-true steps are dropped");
        assert!(steps[0].when.is_none());
        assert!(matches!(steps[1].when, Some(Cond::Test(Test::Method(_)))));
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].to_string().contains("can never hold"));
    }

    #[test]
    fn all_is_ordered_cheapest_first() {
        let (plan, _) = compile_json(
            &site(
                r#"[{"when":{"file":{"root":"/srv","paths":["{path}"]},"pathRegex":"^/a","path":"/a*"},"error":404}]"#,
            ),
            &[],
        )
        .unwrap();
        let Some(Cond::All(tests)) = &plan.sites[0].routes.steps[0].when else {
            panic!("an all");
        };
        let costs: Vec<u8> = tests.iter().map(Cond::cost).collect();
        assert_eq!(costs, [0, 2, 3]);
    }

    #[test]
    fn captures_are_marked_only_where_used() {
        let (plan, _) = compile_json(
            &site(
                r#"[
                {"when":{"pathRegex":"^/(a)$"},"rewrite":"/{re.1}"},
                {"when":{"pathRegex":"^/(a)$"},"rewrite":"/b"}
            ]"#,
            ),
            &[],
        )
        .unwrap();
        let steps = &plan.sites[0].routes.steps;
        assert!(matches!(
            steps[0].when,
            Some(Cond::Test(Test::PathRegex { captures: true, .. }))
        ));
        assert!(matches!(
            steps[1].when,
            Some(Cond::Test(Test::PathRegex {
                captures: false,
                ..
            }))
        ));
        assert_eq!(plan.regexes.len(), 1, "one pattern is compiled once");
    }

    #[test]
    fn includes_are_spliced_with_headers_and_errors() {
        let (plan, _) = compile_json(
            &site(r#"[{"include":"/f.json"},{"error":410}]"#).replace(
                r#""hosts":["a.example"]"#,
                r#""hosts":["a.example"],"headers":{"X-A":"1"},"errors":[{"status":[500],"routes":[{"respond":{}}]}]"#,
            ),
            &[(
                "/f.json",
                r#"{"fragment":1,"headers":{"X-B":"2"},"routes":[{"set":{"v":"1"}},{"set":{"w":"2"}}],"errors":[{"routes":[{"respond":{}}]}]}"#,
            )],
        )
        .unwrap();
        let site = &plan.sites[0];
        assert_eq!(
            site.routes.steps.len(),
            3,
            "the fragment's two steps, in place"
        );
        assert_eq!(site.headers.len(), 2);
        assert_eq!(site.errors.len(), 2);
        assert_eq!(
            site.errors[0].statuses.as_slice(),
            &[Status::INTERNAL_SERVER_ERROR]
        );
        assert!(site.errors[1].statuses.is_empty());
    }

    #[test]
    fn diagnostics_inside_a_fragment_name_the_fragment_and_the_site() {
        let e = errors(
            &site(r#"[{"include":"/f.json"}]"#),
            &[(
                "/f.json",
                r#"{"fragment":1,"routes":[{"name":"x","rewrite":"{nope}"}]}"#,
            )],
        );
        assert_eq!(
            e,
            [
                "/f.json:/routes/0/rewrite: a/x: unknown placeholder `{nope}` (at byte 0 of \"{nope}\")"
            ]
        );
    }

    #[test]
    fn listeners_and_certificates_are_derived() {
        let (plan, _) = compile_json(
            r#"{"version":1,"http3":false,"sites":[
                {"name":"a","hosts":["a.example","www.a.example"],"tls":{"cert":"/c/a.pem","key":"/c/a.key","http3":true},"routes":[]},
                {"name":"b","hosts":["b.example"],"tls":{"cert":"/c/a.pem","key":"/c/a.key"},"routes":[]},
                {"name":"c","hosts":["*"],"routes":[]}
            ]}"#,
            &[],
        )
        .unwrap();
        let keys: Vec<(String, &str)> = plan
            .listeners
            .iter()
            .map(|l| (l.key.addr.to_string(), kind_name(l.key.kind)))
            .collect();
        assert_eq!(
            keys,
            [
                ("0.0.0.0:443".into(), "https"),
                ("0.0.0.0:443".into(), "quic"),
                ("[::]:443".into(), "https"),
                ("[::]:443".into(), "quic"),
                ("0.0.0.0:80".into(), "http"),
                ("[::]:80".into(), "http"),
            ]
        );
        assert_eq!(plan.certs.len(), 1);
        let names: Vec<&str> = plan.certs[0].names.iter().map(|n| &**n).collect();
        assert_eq!(names, ["a.example", "www.a.example", "b.example"]);
        assert_eq!(plan.sites.len(), 4, "three sites and the redirect site");
        assert_eq!(
            plan.sites[0].alt_svc.as_deref(),
            Some(&b"h3=\":443\"; ma=86400"[..])
        );
        assert_eq!(plan.sites[1].alt_svc, None);
        let http = &plan.listeners[4];
        assert_eq!(http.hosts.lookup(b"a.example"), Some(SiteId(3)));
        assert_eq!(http.hosts.lookup(b"other"), Some(SiteId(2)));
        let quic = &plan.listeners[1];
        assert_eq!(quic.hosts.lookup(b"b.example"), None);
    }

    #[test]
    fn sites_naming_one_access_log_share_it() {
        let (plan, _) = compile_json(
            r#"{"version":1,"sites":[
                {"name":"a","hosts":["a.example"],"accessLog":"/var/log/x.log"},
                {"name":"b","hosts":["b.example"]},
                {"name":"c","hosts":["c.example"],"accessLog":"/var/log/y.log",
                 "tls":{"cert":"/c.crt","key":"/c.key"}},
                {"name":"d","hosts":["d.example"],"accessLog":"/var/log/x.log"}
            ]}"#,
            &[],
        )
        .expect("a valid config");
        let logs: Vec<Option<u16>> = plan.sites[..4]
            .iter()
            .map(|s| s.observe.and_then(|o| o.log).map(|l| l.0))
            .collect();
        assert_eq!(logs, [Some(0), None, Some(1), Some(0)]);
        assert_eq!(
            &*plan.access_logs,
            [
                PathBuf::from("/var/log/x.log"),
                PathBuf::from("/var/log/y.log")
            ]
        );
        assert_eq!(plan.sites.len(), 5);
        assert_eq!(
            plan.sites[4].observe, None,
            "the HTTP->HTTPS redirect site logs nothing"
        );
    }

    #[test]
    fn a_relative_access_log_path_is_an_error() {
        let errors = errors(
            r#"{"version":1,"sites":[{"name":"a","hosts":["a.example"],"accessLog":"access.log"}]}"#,
            &[],
        );
        assert_eq!(
            errors,
            ["/sites/0/accessLog: the access log path access.log is not absolute"]
        );
    }

    /// Every terminal of `block`, with its slot's (site, route) label.
    fn labels<'p>(plan: &'p Plan, block: &'p Block, out: &mut Vec<Option<(&'p str, &'p str)>>) {
        for step in block.steps.iter() {
            match &step.action {
                Action::Answer(_, slot) => out.push(slot.map(|s| {
                    let label = &plan.routes[s.0 as usize];
                    (&*label.site, &*label.route)
                })),
                Action::Block(nested) => labels(plan, nested, out),
                _ => {}
            }
        }
    }

    fn labelled(metrics: bool) -> Plan {
        let metrics_site = if metrics {
            r#",{"name":"m","hosts":["*"],"listen":["127.0.0.1:9100"],
                 "routes":[{"name":"scrape","metrics":{}}]}"#
        } else {
            ""
        };
        let json = format!(
            r#"{{"version":1,"sites":[
                {{"name":"a","hosts":["a.example"],
                  "routes":[{{"name":"api","routes":[
                                {{"when":{{"path":"/x"}},"respond":{{}}}},
                                {{"name":"up","when":{{"path":"/up"}},"proxy":"http://127.0.0.1:9"}}]}},
                            {{"error":404}}],
                  "errors":[{{"routes":[{{"respond":{{}}}}]}}]}}{metrics_site}]}}"#
        );
        compile_json(&json, &[]).expect("a valid config").0
    }

    #[test]
    fn terminals_are_labelled_by_their_nearest_named_step_when_metrics_are_collected() {
        let plan = labelled(true);
        assert!(plan.metrics);
        let mut found = Vec::new();
        labels(&plan, &plan.sites[0].routes, &mut found);
        assert_eq!(
            found,
            [Some(("a", "api")), Some(("a", "up")), Some(("a", ""))]
        );
        let mut errors = Vec::new();
        labels(&plan, &plan.sites[0].errors[0].routes, &mut errors);
        assert_eq!(
            errors,
            [None],
            "an error route keeps the failed route's label"
        );
        let mut scrape = Vec::new();
        labels(&plan, &plan.sites[1].routes, &mut scrape);
        assert_eq!(scrape, [Some(("m", "scrape"))]);
        assert!(matches!(
            plan.sites[1].routes.steps[0].action,
            Action::Answer(Terminal::Metrics, _)
        ));
        assert!(
            plan.sites.iter().all(|s| s.observe
                == Some(Observe {
                    log: None,
                    metrics: true
                })),
            "every site observes metrics"
        );
        assert_eq!(
            &*plan.routes[0].site, "",
            "slot 0 is the unlabelled request"
        );
    }

    #[test]
    fn without_a_metrics_step_no_slot_is_stored_and_no_site_observes() {
        let plan = labelled(false);
        assert!(!plan.metrics);
        let mut found = Vec::new();
        labels(&plan, &plan.sites[0].routes, &mut found);
        assert_eq!(found, [None, None, None]);
        assert!(plan.sites.iter().all(|s| s.observe.is_none()));
    }

    #[test]
    fn metrics_open_to_any_address_warn_unless_a_when_guards_them() {
        let (_, warnings) = compile_json(
            &site(r#"[{"name":"m","metrics":{}}]"#).replace(
                r#""hosts":["a.example"]"#,
                r#""hosts":["a.example"],"listen":["0.0.0.0:9100"]"#,
            ),
            &[],
        )
        .unwrap();
        let warnings: Vec<String> = warnings.iter().map(ToString::to_string).collect();
        assert_eq!(
            warnings,
            [
                "warning: /sites/0/routes/0/metrics: metrics are served to anyone who reaches 0.0.0.0:9100; add a `when` or listen on loopback"
            ]
        );
        for guarded in [
            r#"[{"when":{"path":"/metrics"},"metrics":{}}]"#,
            r#"[{"when":{"header":{"x-token":"t"}},"routes":[{"metrics":{}}]}]"#,
        ] {
            let (_, warnings) = compile_json(
                &site(guarded).replace(
                    r#""hosts":["a.example"]"#,
                    r#""hosts":["a.example"],"listen":["0.0.0.0:9100"]"#,
                ),
                &[],
            )
            .unwrap();
            assert!(warnings.is_empty(), "{guarded}: {warnings:?}");
        }
    }

    #[test]
    fn a_single_origin_is_target_origin_and_shares_its_origin() {
        let (plan, _) = compile_json(
            &site(
                r#"[{"when":{"path":"/a"},"proxy":"http://127.0.0.1:9000"},
                    {"proxy":{"to":"http://127.0.0.1:9000/","headers":{"X-A":false}}}]"#,
            ),
            &[],
        )
        .unwrap();
        let targets: Vec<Target> = plan.sites[0]
            .routes
            .steps
            .iter()
            .map(|s| match &s.action {
                Action::Answer(Terminal::Proxy(p), _) => p.to,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(targets, [Target::Origin(OriginId(0)); 2]);
        assert_eq!(plan.origins.len(), 1);
        assert!(plan.pools.is_empty() && plan.sources.is_empty() && plan.limits.is_empty());
        let Action::Answer(Terminal::Proxy(p), _) = &plan.sites[0].routes.steps[1].action else {
            unreachable!()
        };
        let removed = p.headers.iter().find(|h| &*h.name.name == b"x-a").unwrap();
        assert!(removed.value.is_none(), "`false` removes the header");
    }

    #[test]
    fn features_not_built_yet_fail_at_their_pointer() {
        let cases = [
            (
                r#"[{"proxy":{"to":["http://a:1","http://b:1"]}}]"#,
                "/sites/0/routes/0/proxy/to: a list of origins is not supported by this upstreamer yet",
            ),
            (
                r#"[{"proxy":{"to":"http://a:1","balance":"p2c"}}]"#,
                "/sites/0/routes/0/proxy/balance: `balance` is not supported by this upstreamer yet",
            ),
            (
                r#"[{"proxy":{"to":{"kubernetes":{"namespace":"n","service":"s","port":80}}}}]"#,
                "/sites/0/routes/0/proxy/to/kubernetes: this upstreamer is built without Kubernetes support; use the `kubernetes` package",
            ),
            (
                r#"[{"limit":{"rate":"5/s"}}]"#,
                "/sites/0/routes/0/limit: `limit` is not supported by this upstreamer yet",
            ),
        ];
        for (routes, want) in cases {
            assert_eq!(errors(&site(routes), &[]), [want], "{routes}");
        }
        let e = errors(
            r#"{"version":1,"trustedProxies":{"from":["cloudflare"],"header":"CF-Connecting-IP"},"sites":[]}"#,
            &[],
        );
        assert_eq!(
            e,
            ["/trustedProxies: `trustedProxies` is not supported by this upstreamer yet"]
        );
    }

    #[test]
    fn a_tls_site_names_files_or_acme_and_not_both() {
        let tls = |tls: &str| {
            errors(
                &format!(
                    r#"{{"version":1,"sites":[{{"name":"a","hosts":["a.example"],"tls":{tls}}}]}}"#
                ),
                &[],
            )
        };
        assert_eq!(
            tls(r#"{"cert":"/c.pem"}"#),
            ["/sites/0/tls: a TLS site needs `cert` and `key` files, or `acme`"]
        );
        assert_eq!(
            tls(r#"{"cert":"/c.pem","key":"/k.pem","acme":{"email":"ops@example.com"}}"#),
            ["/sites/0/tls: a TLS site takes `cert` and `key`, or `acme`, not both"]
        );
        assert_eq!(
            tls(r#"{"acme":{"email":"ops@example.com"}}"#),
            ["/sites/0/tls/acme: in-process ACME is not supported by this upstreamer yet"]
        );
    }

    #[test]
    fn keys_are_specialised_and_read_the_request_alone() {
        let files = Files(HashMap::new());
        let mut c = Compiler::new(&files);
        let at = Where {
            file: None,
            ptr: "/k".into(),
        };
        let mut vars = Vec::new();
        let mut key = |c: &mut Compiler<'_>, src: &str, captures: Captures| {
            let mut scope = Scope {
                vars: &mut vars,
                captures,
                in_error_route: true,
                uses_captures: false,
                reads: Vec::new(),
            };
            c.key(src, &at, &mut scope)
        };
        assert_eq!(
            key(&mut c, "{remote_host}", Captures::None),
            Some(KeyPlan::RemoteHost)
        );
        assert_eq!(
            key(&mut c, "{remote_net}", Captures::None),
            Some(KeyPlan::RemoteNet)
        );
        assert_eq!(
            key(&mut c, "all", Captures::None),
            Some(KeyPlan::Const(crate::key::constant(b"all")))
        );
        assert!(matches!(
            key(&mut c, "{header.x-api-key}:{remote_net}", Captures::None),
            Some(KeyPlan::Template(_))
        ));
        assert!(c.diags.is_empty(), "{:?}", c.diags);
        assert_eq!(key(&mut c, "{re.1}", Captures::Groups(2)), None);
        assert_eq!(key(&mut c, "{err.status_code}", Captures::None), None);
        assert_eq!(key(&mut c, "", Captures::None), None);
        let messages: Vec<&str> = c.diags.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(
            messages,
            [
                "`{re.1}` cannot be read in a key, which is computed from the request alone (at byte 0 of \"{re.1}\")",
                "`{err.status_code}` has a value only inside an error route (`errors`) (at byte 0 of \"{err.status_code}\")",
                "a key that is always empty never selects a bucket or an origin",
            ]
        );
    }
}
