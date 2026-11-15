//! The compiled runtime plan: what the hot path executes. Built once per (re)load by
//! [`compile::compile`] on the control thread, shared read-only by every core through an `Arc`.
//!
//! Everything the config names by string is an index here: vars ([`VarId`]), regexes
//! ([`RegexId`]), origins ([`OriginId`]), pools ([`PoolId`]), sites ([`SiteId`]). `include`s
//! are spliced, constant matchers folded, templates parsed into typed placeholders. So routing
//! never hashes a var name, never parses a template, and never sees a config type.
//!
//! What the config does not name is absent from the plan, so the request path never tests for
//! it: a site without a `limit` step has no [`Action::Limit`]; a single origin without health
//! settings is [`Target::Origin`]; a plan without a `metrics` step has `metrics == false`,
//! stores no route slot and gives no site an [`Observe`] for metrics; a plan without
//! `trustedProxies` has no `trust`; a plan without in-process ACME has no challenge step.

pub(crate) mod compile;
pub(crate) mod cond;
pub(crate) mod host;
pub(crate) mod load;
pub(crate) mod template;

pub(crate) use load::{check, load};

pub(crate) use cond::Cond;
pub(crate) use host::HostIndex;
pub(crate) use template::Template;

use crate::encode::{Encoding, EncodingSet};
use crate::msg::{HeaderName, Status};
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SiteId(pub u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct VarId(pub u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RegexId(pub u16);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LogId(pub u16);

/// One origin: an index into `upstream::Upstreams::origins`. The origins a config names come
/// first, at the indices [`Plan::origins`] gives them, so a plan's ids are valid in every
/// `Upstreams` built from that plan, whatever discovery adds after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OriginId(pub u16);

/// A pool: an index into [`Plan::pools`] and `upstream::Upstreams::pools` alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PoolId(pub u16);

/// A discovery source: an index into [`Plan::sources`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SourceId(pub u16);

/// A `limit` step's bucket table: an index into [`Plan::limits`] and `limit::Limiters`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LimitId(pub u16);

/// A request series label (site, nearest named step): an index into [`Plan::routes`]. Every
/// terminal and `limit` step of a site's main routes has one while the plan collects metrics;
/// error-route steps have none and leave the request's slot as the main route set it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct RouteSlot(pub u16);

#[derive(Debug)]
pub(crate) struct Plan {
    /// Monotonic per process; cores compare it to drop per-generation caches.
    pub generation: u64,
    pub workers: Option<u16>,
    pub listeners: Box<[ListenerSpec]>,
    pub sites: Box<[SitePlan]>,
    /// The origins the config names, interned by identity ([`OriginSpec::key`]).
    pub origins: Box<[OriginSpec]>,
    /// Every distinct proxy target with more than one bare origin, interned by value.
    pub pools: Box<[PoolPlan]>,
    /// Discovery sources, interned by value. Empty in every build without discovery.
    pub sources: Box<[SourceSpec]>,
    /// Limit tables: what identifies each across reloads, and its size.
    pub limits: Box<[LimitSpec]>,
    /// Request series labels by [`RouteSlot`]. Slot 0 is ("", "") for requests no step took.
    pub routes: Box<[RouteLabel]>,
    /// Some site has a `metrics` step. Derived; nothing else switches collection on.
    pub metrics: bool,
    /// Whose forwarded client address is believed; `None` without `trustedProxies`.
    pub trust: Option<crate::trust::TrustPlan>,
    /// Certificates issued in process, one per site with `tls.acme`.
    pub acme: Box<[crate::acme::AcmePlan]>,
    /// Shared, immutable compiled regexes. Each core keeps its own search caches
    /// (`runtime::RegexCaches`), so matching never contends.
    pub regexes: Box<[regex_automata::meta::Regex]>,
    pub var_count: u16,
    /// Var names by [`VarId`], for logs and tests.
    pub var_names: Box<[Box<str>]>,
    /// Certificate files to load, one per TLS site (sites sharing files share an entry).
    pub certs: Box<[CertSource]>,
    /// Access log files by [`LogId`], each path once however many sites write to it. Opened
    /// by the control thread at every (re)load, never by `check`.
    pub access_logs: Box<[PathBuf]>,
    pub server: ServerParams,
    /// `sites[..user_sites]` are the config's sites, in order; the rest are synthetic (the
    /// HTTP->HTTPS redirect site).
    pub user_sites: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct ServerParams {
    pub header_timeout: Duration,
    pub keep_alive: Duration,
    pub shutdown: Duration,
    pub max_head_bytes: u32,
    pub max_header_fields: u16,
    pub max_streams: u32,
}

impl Default for ServerParams {
    /// The values a config gets for every `timeouts`/`limits` key it leaves out.
    fn default() -> Self {
        ServerParams {
            header_timeout: Duration::from_secs(10),
            keep_alive: Duration::from_secs(75),
            shutdown: Duration::from_secs(10),
            max_head_bytes: 32 * 1024,
            max_header_fields: 100,
            max_streams: 128,
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
    /// `Some` exactly when the site logs or the plan collects metrics; the pipeline tests
    /// this one `Option` per request.
    pub observe: Option<Observe>,
}

/// What happens to a finished request of a site: its access log line, its metrics, or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observe {
    pub log: Option<LogId>,
    pub metrics: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteLabel {
    pub site: Box<str>,
    /// The nearest enclosing named step's name, `""` when none.
    pub route: Box<str>,
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
    /// Takes a token from a shared bucket or answers 429. Never inside error routes.
    Limit(LimitPlan),
    /// A terminal, with the series label it gives the request: `Some` in the main routes of a
    /// plan that collects metrics, `None` otherwise (nothing is stored).
    Answer(Terminal, Option<RouteSlot>),
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
    /// The Prometheus exposition of the whole process.
    Metrics,
    /// An ACME HTTP-01 token (`/.well-known/acme-challenge/<token>`), on the HTTP->HTTPS
    /// redirect site of a plan with in-process ACME.
    AcmeChallenge,
}

/// One `limit` step.
#[derive(Debug)]
pub(crate) struct LimitPlan {
    pub table: LimitId,
    pub key: KeyPlan,
    /// The emission interval and the burst tolerance, in the table's time unit (see
    /// `limit::Table`): a request is admitted while its key's theoretical arrival time stays
    /// within `tolerance` of now.
    pub interval: u64,
    pub tolerance: u64,
    /// The label of a 429 this step answers.
    pub route: RouteSlot,
}

/// What a limit table is across reloads: the same site, step path and key template keep their
/// buckets; anything else starts empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LimitSpec {
    pub site: Box<str>,
    pub step: Box<str>,
    pub key: Box<str>,
    /// Bucket slots, a power of two of at least 8 (a constant key gets 8: one cache line).
    pub slots: u32,
    /// Bits of a slot word that hold the arrival time; the rest is the key's fingerprint.
    pub unit_shift: u8,
}

/// A request key for a limit or a hash policy, specialised at compile time.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyPlan {
    /// `{remote_host}`: the client address's bytes are hashed, never formatted.
    RemoteHost,
    /// `{remote_net}`: an IPv4 address, or an IPv6 address's /64.
    RemoteNet,
    /// A constant: one bucket, one hash value.
    Const(u64),
    /// Anything else, expanded into the arena and hashed. An empty expansion is "no key".
    Template(Template),
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
    pub to: Target,
    /// Defaults first (X-Forwarded-*), then the config's, so the config can override or remove
    /// a default.
    pub headers: Box<[HeaderOp]>,
    pub dial_timeout: Duration,
    pub response_header_timeout: Option<Duration>,
    pub tunnel_idle: Option<Duration>,
}

/// Where a proxy step sends its requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// One origin, no balancing, no health settings: pooled connections, one retry on a fresh
    /// connection when a pooled one turns out dead.
    Origin(OriginId),
    /// Several origins, a discovered member set, or any health setting.
    Pool(PoolId),
}

/// One balanced target. Interned by value: steps with equal targets share it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PoolPlan {
    pub members: MembersPlan,
    pub balance: BalancePlan,
    /// Further attempts after a failed one, for replayable requests.
    pub retries: u8,
    /// Origin statuses that count as failed attempts.
    pub fail_statuses: StatusSet,
    /// `None`: passive checks off (`maxFails = 0`).
    pub passive: Option<PassivePlan>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MembersPlan {
    /// Origins from the config with their weights (weight 0 drains: never picked).
    Static(Box<[(OriginId, u16)]>),
    /// Whatever the source reports, weight 1 each.
    Discovered(SourceId),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BalancePlan {
    RoundRobin,
    LeastRequests,
    P2c,
    Hash(KeyPlan),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PassivePlan {
    pub max_fails: u8,
    /// Whole seconds (the health clock's unit).
    pub cooldown: u32,
}

/// One origin. Proxy steps naming the same origin share its per-core connection pools and its
/// health. Static origins live in [`Plan::origins`]; discovered ones are built from
/// [`SourceSpec`] by the upstream registry.
#[derive(Debug, Clone)]
pub(crate) struct OriginSpec {
    pub host: Box<str>,
    pub port: u16,
    /// Literal IPs are resolved at compile time; names (`storage`, `localhost`) when dialled,
    /// cached per core with a TTL, so a name that does not resolve yet (tailscale down at
    /// boot) never fails a load.
    pub addr: OriginAddr,
    pub tls: Option<UpstreamTls>,
    pub idle: Duration,
    pub max_idle_per_core: u16,
    /// The origin's active check, if a step gave it one.
    pub probe: Option<ProbePlan>,
}

/// What makes two origins the same origin: the compiler interns by it, the registry carries
/// health by it, the per-core pools keep idle connections across epochs by it. Derived from
/// the spec by [`OriginSpec::key`], never stored beside it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OriginKey {
    pub https: bool,
    pub host: Box<str>,
    pub port: u16,
    pub server_name: Option<Box<str>>,
    pub verify: bool,
}

impl OriginSpec {
    pub fn key(&self) -> OriginKey {
        OriginKey {
            https: self.tls.is_some(),
            host: self.host.clone(),
            port: self.port,
            server_name: self.tls.as_ref().and_then(|t| t.server_name.clone()),
            verify: self.tls.as_ref().is_none_or(|t| t.verify),
        }
    }
}

/// An origin's active health check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProbePlan {
    /// `GET <path> HTTP/1.1`, `Host: <host>`, `Connection: close`, written once here.
    pub request: Box<[u8]>,
    pub interval: Duration,
    pub timeout: Duration,
    pub expect: StatusSet,
    pub healthy_after: u8,
    pub unhealthy_after: u8,
}

/// Statuses 100..=599 as a bitset: membership is one shift and mask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct StatusSet([u64; 8]);

impl StatusSet {
    /// `None` for a code outside 100..=599.
    pub fn insert(&mut self, code: u16) -> Option<()> {
        let bit = usize::from(code.checked_sub(100).filter(|&b| b < 500)?);
        self.0[bit / 64] |= 1 << (bit % 64);
        Some(())
    }
    pub fn contains(&self, status: Status) -> bool {
        let Some(bit) = status.code().checked_sub(100).filter(|&b| b < 500) else {
            return false;
        };
        let bit = usize::from(bit);
        self.0[bit / 64] & (1 << (bit % 64)) != 0
    }
}

/// A discovery source and the settings its origins get.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum SourceSpec {
    Kubernetes(KubeSource),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct KubeSource {
    /// What the watch observes: its identity across reloads (`discover::SourceKey`). Changing
    /// a setting below keeps the watch and its last endpoints.
    pub watch: Arc<KubeWatch>,
    pub https: bool,
    pub server_name: Option<Box<str>>,
    pub verify: bool,
    pub idle: Duration,
    /// The probe every origin of this source gets.
    pub probe: Option<ProbePlan>,
    /// The label its origins' metrics aggregate under: `kubernetes:<ns>/<service>:<port>` or
    /// `kubernetes:<ns>/<selector>:<port>`.
    pub label: Box<str>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct KubeWatch {
    pub namespace: Box<str>,
    pub select: KubeSelect,
    pub port: KubePort,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum KubeSelect {
    Service(Box<str>),
    Labels(Box<str>),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum KubePort {
    Number(u16),
    Name(Box<str>),
}

#[derive(Debug, Clone)]
pub(crate) enum OriginAddr {
    Ip(SocketAddr),
    Name,
}

#[derive(Debug, Clone)]
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

impl Plan {
    /// Host routing for a request on `listener`. `None` -> 421 on TLS listeners, 404 on
    /// cleartext ones. `host` is lowercase without port (as `RequestHead::host` keeps it).
    pub fn site_for(&self, listener: &ListenerKey, host: &[u8]) -> Option<(SiteId, &SitePlan)> {
        let spec = self.listeners.iter().find(|l| l.key == *listener)?;
        let id = spec.hosts.lookup(host)?;
        Some((id, &self.sites[id.0 as usize]))
    }
}
