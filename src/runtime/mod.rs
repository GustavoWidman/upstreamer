//! Thread-per-core. One worker per CPU of the process's affinity mask, each pinned to its CPU,
//! each running a current-thread tokio runtime with a `LocalSet`. A core owns:
//! its listeners, its connections, its upstream pools, buffer and exchange pools, regex caches,
//! file catalog and coarse clock. It shares nothing mutable with other cores.
//!
//! The control thread (the process's main thread) owns the truth: it compiles plans, loads
//! certificates, rotates ticket keys, follows discovery sources, and publishes a
//! [`Generation`] to every core over a channel. A core installs it between requests:
//! connections read [`Core::snapshot`] once per request (an `Rc` clone, no atomic), so a
//! reload takes effect on the next request of every keep-alive connection, and an in-flight
//! request finishes under the plan it started with.
//!
//! Cores share only immutable `Arc`s, with two named exceptions: the health cells inside
//! `upstream::Upstreams` (relaxed loads on the request path, writes on health transitions) and
//! the bucket tables inside `limit::Limiters` (one compare-and-swap per limited request).
//! Metrics are not an exception: their counters are core-owned `Cell`s, published by the core
//! itself once a second.

pub(crate) mod control;
pub(crate) mod handover;
#[cfg(any(test, feature = "internals"))]
pub mod harness;
pub(crate) mod slots;

use crate::StartError;
use crate::access;
use crate::acme;
use crate::exchange::{ConnInfo, ExchangePool, Proto, Scheme};
use crate::files::catalog::Catalog;
use crate::limit::Limiters;
use crate::log::{debug, warning};
use crate::metrics;
use crate::net::buf::BufPool;
use crate::net::listen::{self, Inherited, Listener, SocketKind};
use crate::net::{Socket, Transport};
use crate::plan::{ListenerKey, ListenerKind, Plan, RegexId, ServerParams};
use crate::proxy::pool::Pools;
use crate::tls::{self, CertStore, TicketKeys};
use crate::upstream::{Registry, Upstreams};
use std::cell::{Cell, RefCell};
use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::rc::Rc;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;

/// What the control thread publishes: immutable, shared by all cores. `Clone`, so a publish
/// that changes one part (a ticket rotation, a discovery change) writes
/// `Generation { part, ..(*current).clone() }`.
#[derive(Clone)]
pub(crate) struct Generation {
    pub plan: Arc<Plan>,
    /// The origins and pool members of this epoch: a new `Arc` on every reload and every
    /// discovery change.
    pub upstreams: Arc<Upstreams>,
    /// The plan's limit tables, carried across reloads by `LimitSpec`.
    pub limits: Arc<Limiters>,
    /// `Some` when the plan collects metrics: the counter layout of this plan and epoch, and
    /// the process's hub (the same `Arc` in every generation).
    pub metrics: Option<(Arc<metrics::Layout>, Arc<metrics::Hub>)>,
    /// `Some` when the plan has in-process ACME: the validation answers of pending orders.
    pub acme: Option<Arc<acme::Challenges>>,
    /// Present exactly when the plan has a TLS or QUIC listener.
    pub tls: Option<TlsState>,
    /// The plan's access log files, opened for this generation.
    pub access: Arc<access::Files>,
}

impl Generation {
    /// A generation that carries nothing over from an earlier one: fresh health, empty limit
    /// tables, a hub of its own.
    pub fn standalone(plan: Plan, tls: Option<TlsState>, access: Arc<access::Files>) -> Generation {
        let plan = Arc::new(plan);
        let upstreams = Registry::new(1).build(&plan);
        let metrics = plan.metrics.then(|| {
            (
                metrics::Layout::build(&plan, &upstreams),
                metrics::Hub::new(allowed_cpus().len()),
            )
        });
        Generation {
            limits: Limiters::carry(&plan, None),
            upstreams,
            metrics,
            acme: None,
            tls,
            access,
            plan,
        }
    }
}

/// Certificates and ticket keys of a generation. Ticket keys are shared by every core, so a
/// session ticket issued on one core resumes on another.
#[derive(Clone)]
pub(crate) struct TlsState {
    pub certs: Arc<CertStore>,
    pub tickets: Arc<TicketKeys>,
}

/// A core's view of one generation, built on the core when the generation arrives (so the
/// rustls configs and the metrics counters are this core's own).
pub(crate) struct CoreSnapshot {
    pub plan: Arc<Plan>,
    pub upstreams: Arc<Upstreams>,
    pub limits: Arc<Limiters>,
    /// This core's counters for this snapshot; folded into the core's retired totals when the
    /// snapshot's last holder (the core, or a request still running under it) drops it.
    pub metrics: Option<metrics::Counters>,
    pub acme: Option<Arc<acme::Challenges>>,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub quic: Option<Arc<rustls::ServerConfig>>,
    pub access: Arc<access::Files>,
    /// What `tls` and `quic` were built from.
    tls_state: Option<TlsState>,
}

impl CoreSnapshot {
    /// Reuses `previous`'s rustls configs when the plan, the certificates and the ticket keys
    /// are the same `Arc`s, so a discovery change rebuilds nothing TLS.
    fn new(
        generation: &Generation,
        previous: Option<&CoreSnapshot>,
        retired: &Rc<RefCell<metrics::Retired>>,
    ) -> CoreSnapshot {
        let plan = generation.plan.clone();
        let same_tls = previous.filter(|p| {
            Arc::ptr_eq(&p.plan, &plan)
                && match (&p.tls_state, &generation.tls) {
                    (Some(a), Some(b)) => {
                        Arc::ptr_eq(&a.certs, &b.certs) && Arc::ptr_eq(&a.tickets, &b.tickets)
                    }
                    (None, None) => true,
                    _ => false,
                }
        });
        let (tls, quic) = match (same_tls, &generation.tls) {
            (Some(p), _) => (p.tls.clone(), p.quic.clone()),
            (None, None) => (None, None),
            (None, Some(state)) => {
                let has = |kind| plan.listeners.iter().any(|l| l.key.kind == kind);
                (
                    has(ListenerKind::Https)
                        .then(|| tls::server_config(state.certs.clone(), state.tickets.clone())),
                    has(ListenerKind::Quic).then(|| {
                        tls::quic_server_config(state.certs.clone(), state.tickets.clone())
                    }),
                )
            }
        };
        CoreSnapshot {
            plan,
            upstreams: generation.upstreams.clone(),
            limits: generation.limits.clone(),
            metrics: generation.metrics.as_ref().map(|(layout, hub)| {
                metrics::Counters::new(layout.clone(), hub.clone(), retired.clone())
            }),
            acme: generation.acme.clone(),
            tls,
            quic,
            access: generation.access.clone(),
            tls_state: generation.tls.clone(),
        }
    }
}

/// Search caches for the plan's regexes, one per regex, owned by the core.
pub(crate) struct RegexCaches {
    pub caches: Vec<regex_automata::meta::Cache>,
    generation: u64,
}

impl RegexCaches {
    /// One cache per regex of `plan`, indexed by `RegexId`.
    pub fn for_plan(plan: &Plan) -> RegexCaches {
        RegexCaches {
            caches: plan.regexes.iter().map(|r| r.create_cache()).collect(),
            generation: plan.generation,
        }
    }
    /// The cache for `id` of `plan`. A request that started before a reload still matches with
    /// its own plan's regexes, so the caches follow the plan they are asked for.
    pub fn get(&mut self, plan: &Plan, id: RegexId) -> &mut regex_automata::meta::Cache {
        if self.generation != plan.generation {
            *self = RegexCaches::for_plan(plan);
        }
        &mut self.caches[id.0 as usize]
    }
}

/// The process-wide origin of the health clock ([`Clock::mono`]), set once before the cores
/// start, so every core counts the same seconds.
pub(crate) static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Nanoseconds on the clock `Instant` reads, as one integer: a duration between two readings
/// is one subtraction, where `Instant`'s is a checked subtraction of seconds and nanoseconds.
/// For what a request measures per request: its duration, its upstream's, a rate limit's
/// arrival time.
///
/// The same clock as `Instant` on every platform, so a span read with one agrees with the
/// other: `CLOCK_MONOTONIC` on Linux, `CLOCK_UPTIME_RAW` on macOS, where `CLOCK_MONOTONIC` is
/// frequency-adjusted to network time and drifts from `Instant` while the system clock is
/// being corrected.
pub(crate) fn monotonic_nanos() -> u64 {
    #[cfg(target_vendor = "apple")]
    const CLOCK: libc::clockid_t = libc::CLOCK_UPTIME_RAW;
    #[cfg(not(target_vendor = "apple"))]
    const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec; CLOCK is always available.
    unsafe { libc::clock_gettime(CLOCK, &mut ts) };
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

/// Coarse clock: unix seconds and the formatted `Date` value, refreshed once per second by a
/// core-local timer (no `clock_gettime` or formatting per response).
pub(crate) struct Clock {
    pub unix: Cell<i64>,
    /// Whole seconds since [`START`]: the health clock (ejections and probes).
    pub mono: Cell<u32>,
    pub http_date: RefCell<[u8; 29]>,
    /// The system time and [`monotonic_nanos`] read together at the last tick, so a
    /// monotonic reading converts to wall time without another clock read.
    anchor: Cell<(Duration, u64)>,
}

impl Clock {
    /// Reads the system clock now; the core's timer calls [`Clock::tick`] every second.
    pub fn new() -> Clock {
        let clock = Clock {
            unix: Cell::new(0),
            mono: Cell::new(0),
            http_date: RefCell::new(*b"Thu, 01 Jan 1970 00:00:00 GMT"),
            anchor: Cell::new((Duration::ZERO, 0)),
        };
        clock.tick();
        clock
    }
    /// Refreshes `unix` and `http_date` (IMF-fixdate) from the system clock.
    pub fn tick(&self) {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.anchor.set((wall, monotonic_nanos()));
        let now = Instant::now();
        let start = *START.get_or_init(|| now);
        self.mono
            .set(now.saturating_duration_since(start).as_secs() as u32);
        let now = wall.as_secs() as i64;
        if now != self.unix.get() {
            self.unix.set(now);
            *self.http_date.borrow_mut() = imf_fixdate(now);
        }
    }
    /// The time since the Unix epoch at `at`, a [`monotonic_nanos`] reading taken after the
    /// last tick.
    pub fn wall(&self, at: u64) -> Duration {
        let (wall, anchor) = self.anchor.get();
        wall + Duration::from_nanos(at.saturating_sub(anchor))
    }
}

/// The proleptic Gregorian (year, month, day) of a day count since 1970-01-01 (Howard
/// Hinnant's algorithm).
pub(crate) fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `Sun, 06 Nov 1994 08:49:37 GMT` (RFC 9110 section 5.6.7) for unix seconds `t`.
fn imf_fixdate(t: i64) -> [u8; 29] {
    const DAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
    const MONTHS: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (year, month, day) = civil(days);

    let mut out = *b"Thu, 01 Jan 1970 00:00:00 GMT";
    out[..3].copy_from_slice(DAYS[days.rem_euclid(7) as usize]);
    let digits = |out: &mut [u8], value: i64| {
        let mut v = value;
        for slot in out.iter_mut().rev() {
            *slot = b'0' + (v % 10) as u8;
            v /= 10;
        }
    };
    digits(&mut out[5..7], day);
    out[8..11].copy_from_slice(MONTHS[(month - 1) as usize]);
    digits(&mut out[12..16], year);
    digits(&mut out[17..19], secs / 3600);
    digits(&mut out[20..22], secs / 60 % 60);
    digits(&mut out[23..25], secs % 60);
    out
}

/// A listening socket of this core and the task that serves it.
struct Bound {
    key: ListenerKey,
    task: JoinHandle<()>,
    /// A second descriptor of the socket, for the process this one hands over to.
    socket: OwnedFd,
    quic: Option<Quic>,
}

/// The QUIC side of a listener.
#[derive(Clone)]
struct Quic {
    /// Kept to swap its TLS config at reload.
    endpoint: quinn::Endpoint,
    /// quinn's hold on the UDP socket: gone once nothing in this process reads it.
    io: Weak<dyn quinn::AsyncUdpSocket>,
}

/// The listeners a core does not serve yet. A process that takes over from another starts
/// with every listener held, so it touches no connection before the other process lets go,
/// and keeps the QUIC ones held while the other still reads their sockets: a datagram is
/// read by one process only, and the other's connections need theirs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hold {
    All,
    Quic,
    Nothing,
}

impl Hold {
    fn covers(self, transport: SocketKind) -> bool {
        match self {
            Hold::All => true,
            Hold::Quic => transport == SocketKind::Udp,
            Hold::Nothing => false,
        }
    }
}

/// How a core stops.
#[derive(Clone)]
pub(crate) struct Drain {
    /// Whatever is still open then is cut.
    pub deadline: Instant,
    /// When idle keep-alive connections close. Until then a request that arrives on one is
    /// answered, with `Connection: close`.
    pub idle_close: Instant,
    /// Dropped once this core reads none of its UDP sockets any more.
    pub released: Option<Arc<OwnedFd>>,
}

impl Drain {
    /// The process stops: idle connections close at once.
    pub fn stop(deadline: Instant) -> Drain {
        Drain {
            deadline,
            idle_close: Instant::now(),
            released: None,
        }
    }
}

/// A listener that could not be bound on a core.
#[derive(Debug)]
pub(crate) struct BindFailure {
    pub addr: SocketAddr,
    pub error: io::Error,
}

pub(crate) struct Core {
    pub index: usize,
    snapshot: RefCell<Rc<CoreSnapshot>>,
    pub regex: RefCell<RegexCaches>,
    pub catalog: RefCell<Catalog>,
    pub bufs: BufPool,
    pub exchanges: ExchangePool,
    /// Blocks the HTTP/1.1 driver runs each request in.
    pub requests: slots::Slots,
    pub upstreams: Pools,
    pub clock: Clock,
    /// This core's access log buffers; written when the core drops.
    pub access: access::Writer,
    /// Totals of this core's dropped snapshots' metrics; live snapshots fold into it.
    pub retired: Rc<RefCell<metrics::Retired>>,
    /// Accepted connections and handshakes per listener, kept always: one `Cell` add per
    /// connection and per handshake, never per request.
    pub connections: metrics::ConnCounters,
    pub draining: Cell<bool>,
    /// Woken once, when draining starts.
    drain_started: Notify,
    /// Set when idle keep-alive connections are to close: when a stop starts, later when
    /// another process took the listeners over and nothing waits for this one.
    pub closing_idle: Cell<bool>,
    /// Woken once, when `closing_idle` is set.
    idle_close_started: Notify,
    /// Open downstream connections.
    conns: Cell<usize>,
    /// Woken when the last connection of a draining core ends.
    conns_closed: Notify,
    listeners: RefCell<Vec<Bound>>,
    hold: Cell<Hold>,
    /// Sockets handed to this core that no listener has taken.
    inherited: RefCell<Vec<Inherited>>,
}

impl Core {
    /// A core for `generation` with no listener bound yet.
    fn new(index: usize, generation: &Generation) -> Core {
        let retired = Rc::default();
        Core {
            index,
            snapshot: RefCell::new(Rc::new(CoreSnapshot::new(generation, None, &retired))),
            regex: RefCell::new(RegexCaches::for_plan(&generation.plan)),
            catalog: RefCell::default(),
            bufs: BufPool::default(),
            exchanges: ExchangePool::default(),
            requests: slots::Slots::default(),
            upstreams: Pools::default(),
            clock: Clock::new(),
            access: access::Writer::new(generation.access.clone()),
            retired,
            connections: metrics::ConnCounters::default(),
            draining: Cell::new(false),
            drain_started: Notify::new(),
            closing_idle: Cell::new(false),
            idle_close_started: Notify::new(),
            conns: Cell::new(0),
            conns_closed: Notify::new(),
            listeners: RefCell::default(),
            hold: Cell::new(Hold::Nothing),
            inherited: RefCell::default(),
        }
    }
    /// The current snapshot. Held by a request for its duration; never across requests.
    pub fn snapshot(&self) -> Rc<CoreSnapshot> {
        self.snapshot.borrow().clone()
    }
    /// Installs a new generation: builds this core's TLS configs and regex caches, re-indexes
    /// upstream pools, binds listeners whose key is new and closes those whose key is gone
    /// (their connections keep running). Returns the listeners that could not be bound; they
    /// are retried by the next install that still lists them.
    ///
    /// When the plan is the same `Arc` (a discovery change, a ticket rotation), the regex
    /// caches, the file catalog and the per-pool state stay; when only the upstream table
    /// changed, the origin slots are re-indexed by identity.
    pub async fn install(self: &Rc<Self>, generation: &Generation) -> Vec<BindFailure> {
        let old = self.snapshot();
        let new = Rc::new(CoreSnapshot::new(generation, Some(&old), &self.retired));
        if !Arc::ptr_eq(&old.plan, &new.plan) {
            *self.regex.borrow_mut() = RegexCaches::for_plan(&new.plan);
            self.catalog.borrow_mut().retain_immutable();
            self.upstreams.reset_pools();
        }
        if !Arc::ptr_eq(&old.upstreams, &new.upstreams)
            && !(old.upstreams.origins().is_empty() && new.upstreams.origins().is_empty())
        {
            self.upstreams.adopt(&old.upstreams, &new.upstreams);
        }
        self.access.adopt(&new.access);
        *self.snapshot.borrow_mut() = new.clone();
        self.sync_listeners(&new).await
    }
    /// Makes the bound listeners match the snapshot's plan, by key, leaving out the held ones.
    /// An inherited socket that no listener of the plan takes is closed, unless it is held.
    async fn sync_listeners(self: &Rc<Self>, snap: &CoreSnapshot) -> Vec<BindFailure> {
        let hold = self.hold.get();
        let wanted = &snap.plan.listeners;
        let (kept, gone): (Vec<Bound>, Vec<Bound>) = self
            .listeners
            .take()
            .into_iter()
            .partition(|b| wanted.iter().any(|l| l.key == b.key));
        close(gone).await;
        let mut bound = kept;
        let mut failures = Vec::new();
        for spec in wanted
            .iter()
            .filter(|l| !hold.covers(SocketKind::of(l.key.kind)))
        {
            match bound.iter().find(|b| b.key == spec.key) {
                Some(b) => {
                    if let (Some(quic), Some(config)) = (&b.quic, &snap.quic) {
                        match quic_config(config.clone(), &snap.plan.server) {
                            Ok(config) => quic.endpoint.set_server_config(Some(config)),
                            Err(error) => failures.push(BindFailure {
                                addr: spec.key.addr,
                                error,
                            }),
                        }
                    }
                }
                None => match self.listen(spec.key, snap) {
                    Ok(b) => bound.push(b),
                    Err(error) => failures.push(BindFailure {
                        addr: spec.key.addr,
                        error,
                    }),
                },
            }
        }
        *self.listeners.borrow_mut() = bound;
        self.inherited
            .borrow_mut()
            .retain(|socket| hold.covers(socket.transport));
        failures
    }
    /// Serves `key` on the socket inherited for it, or binds one.
    fn listen(self: &Rc<Self>, key: ListenerKey, snap: &CoreSnapshot) -> io::Result<Bound> {
        let inherited = {
            let mut sockets = self.inherited.borrow_mut();
            let found = sockets.iter().position(|socket| socket.serves(key));
            found.map(|at| sockets.swap_remove(at))
        };
        let fd = match inherited {
            Some(socket) => socket.adopt()?,
            None => listen::bind(key.addr, key.kind)?,
        };
        let socket = fd.try_clone()?;
        match key.kind {
            ListenerKind::Http | ListenerKind::Https => {
                let listener = Listener::new(key, fd)?;
                let task = tokio::task::spawn_local(accept_loop(self.clone(), listener));
                Ok(Bound {
                    key,
                    task,
                    socket,
                    quic: None,
                })
            }
            ListenerKind::Quic => {
                let config = snap
                    .quic
                    .clone()
                    .ok_or_else(|| io::Error::other("QUIC listener without a TLS config"))?;
                let (endpoint, io) =
                    listen::quic_endpoint(fd, quic_config(config, &snap.plan.server)?)?;
                let task =
                    tokio::task::spawn_local(quic_accept_loop(self.clone(), key, endpoint.clone()));
                Ok(Bound {
                    key,
                    task,
                    socket,
                    quic: Some(Quic { endpoint, io }),
                })
            }
        }
    }
    /// Narrows the hold and serves the listeners it no longer covers.
    async fn release(self: &Rc<Self>, hold: Hold) -> Vec<BindFailure> {
        self.hold.set(hold);
        self.sync_listeners(&self.snapshot()).await
    }
    /// A descriptor of every listening socket of this core, for the process that takes over:
    /// those it serves and those it still holds for a process it took over from itself.
    fn sockets(&self) -> Vec<Inherited> {
        let listeners = self.listeners.borrow();
        let served = listeners.iter().map(|bound| {
            (
                SocketKind::of(bound.key.kind),
                bound.key.addr,
                &bound.socket,
            )
        });
        let inherited = self.inherited.borrow();
        let held = inherited.iter().map(|s| (s.transport, s.addr, &s.fd));
        served
            .chain(held)
            .filter_map(|(transport, addr, fd)| {
                Some(Inherited {
                    transport,
                    addr,
                    fd: fd.try_clone().ok()?,
                })
            })
            .collect()
    }
    /// Resolves once draining has started: connections stop taking new work and finish
    /// what they have.
    pub async fn until_drain(&self) {
        if !self.draining.get() {
            self.drain_started.notified().await;
        }
    }
    /// Resolves once idle keep-alive connections are to close. They wait on it while idle.
    pub async fn until_idle_close(&self) {
        if !self.closing_idle.get() {
            self.idle_close_started.notified().await;
        }
    }
    fn close_idle(&self) {
        self.closing_idle.set(true);
        self.idle_close_started.notify_waiters();
    }
    /// Counts a connection accepted on `key` until the guard drops, so draining knows when
    /// the core is empty and the listener's metrics count it as closed.
    fn track(self: &Rc<Self>, key: ListenerKey) -> ConnGuard {
        self.connections.accepted(key);
        self.conns.set(self.conns.get() + 1);
        ConnGuard {
            core: self.clone(),
            key,
        }
    }
    /// Stops accepting and waits for the connections to finish until the deadline. Whatever is
    /// still open then is cut when the runtime drops. Idle keep-alive connections close at
    /// `idle_close`; QUIC endpoints end on their own once their connections have.
    async fn drain(&self, drain: Drain) {
        self.draining.set(true);
        self.drain_started.notify_waiters();
        if drain.idle_close <= Instant::now() {
            self.close_idle();
        }
        let listeners = self.listeners.take();
        let endpoints: Vec<Quic> = listeners.iter().filter_map(|b| b.quic.clone()).collect();
        close(listeners).await;
        let deadline = tokio::time::Instant::from_std(drain.deadline);
        let idle_close = tokio::time::Instant::from_std(drain.idle_close);
        let connections = async {
            while self.conns.get() > 0 {
                tokio::select! {
                    closed = tokio::time::timeout_at(deadline, self.conns_closed.notified()) => {
                        if closed.is_err() {
                            warning!(
                                "core {}: {} connections cut at the shutdown deadline",
                                self.index,
                                self.conns.get()
                            );
                            break;
                        }
                    }
                    () = tokio::time::sleep_until(idle_close), if !self.closing_idle.get() => {
                        self.close_idle();
                    }
                }
            }
        };
        // The connections' closing packets go out while their endpoints still run. At the
        // deadline the connections still open are closed rather than dropped, so their clients
        // learn at once instead of after their idle timeout.
        let datagrams = async {
            let mut sockets = Vec::with_capacity(endpoints.len());
            for Quic { endpoint, io } in endpoints {
                if tokio::time::timeout_at(deadline, endpoint.wait_idle())
                    .await
                    .is_err()
                {
                    endpoint.close(H3_NO_ERROR, b"");
                    let _ = tokio::time::timeout(CLOSE_GRACE, endpoint.wait_idle()).await;
                }
                sockets.push(io);
            }
            if let Some(released) = drain.released {
                // An endpoint's driver stops reading once the last handle on the endpoint is
                // gone, the next time it runs.
                let stopped = async {
                    while sockets.iter().any(|io| io.strong_count() > 0) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                };
                let _ = tokio::time::timeout_at(deadline + CLOSE_GRACE, stopped).await;
                drop(released);
            }
        };
        tokio::join!(connections, datagrams);
    }
}

/// The HTTP/3 application error code of a connection closed without an error (RFC 9114
/// section 8.1).
const H3_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x100);

/// How long past the shutdown deadline QUIC endpoints get to send the close of the
/// connections they cut. The unit's stop timeout leaves seconds for it.
const CLOSE_GRACE: Duration = Duration::from_millis(100);

fn quic_config(
    config: Arc<rustls::ServerConfig>,
    server: &ServerParams,
) -> io::Result<quinn::ServerConfig> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(crate::proto::h3::transport(server));
    Ok(config)
}

/// Closes listeners. A TCP listener's socket is closed when this returns. A QUIC endpoint
/// stops taking new connections and keeps its socket until its open connections end, since
/// their packets arrive on it.
async fn close(listeners: Vec<Bound>) {
    for b in listeners {
        if let Some(quic) = &b.quic {
            quic.endpoint.set_server_config(None);
        }
        b.task.abort();
        let _ = b.task.await;
    }
}

/// Accept loop of one QUIC endpoint: a local task per incoming connection.
async fn quic_accept_loop(core: Rc<Core>, key: ListenerKey, endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        let guard = core.track(key);
        let core = core.clone();
        tokio::task::spawn_local(async move {
            crate::proto::h3::serve(core, incoming, key).await;
            drop(guard);
        });
    }
}

struct ConnGuard {
    core: Rc<Core>,
    key: ListenerKey,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.core.connections.closed(self.key);
        let left = self.core.conns.get() - 1;
        self.core.conns.set(left);
        if left == 0 && self.core.draining.get() {
            self.core.conns_closed.notify_one();
        }
    }
}

/// Messages from the control thread to a core.
pub(crate) enum ToCore {
    /// Install the generation, then report the listeners that could not be bound.
    Install(Arc<Generation>, oneshot::Sender<Vec<BindFailure>>),
    /// Narrow the hold, serve the listeners it no longer covers, then report those that could
    /// not be bound.
    Release(Hold, oneshot::Sender<Vec<BindFailure>>),
    /// Report a descriptor of every listening socket of the core.
    Sockets(oneshot::Sender<Vec<Inherited>>),
    /// Stop accepting, GOAWAY, finish in-flight within the deadline.
    Drain(Drain),
}

/// Handle the control thread keeps per core.
pub(crate) struct Worker {
    pub thread: std::thread::JoinHandle<()>,
    pub tx: mpsc::UnboundedSender<ToCore>,
    pub cpu: usize,
}

/// Spawns one pinned worker per CPU. Each binds its listeners for the initial generation
/// before reporting ready; a bind failure on any core is a start failure.
pub(crate) fn spawn_workers(
    cpus: &[usize],
    initial: Arc<Generation>,
) -> Result<Vec<Worker>, StartError> {
    spawn_workers_with(cpus, initial, Vec::new(), Hold::Nothing)
}

/// [`spawn_workers`] for a process that was handed sockets: each core serves a listener on a
/// socket inherited for it when there is one, and leaves the held listeners for a later
/// [`ToCore::Release`].
pub(crate) fn spawn_workers_with(
    cpus: &[usize],
    initial: Arc<Generation>,
    inherited: Vec<Inherited>,
    hold: Hold,
) -> Result<Vec<Worker>, StartError> {
    let mut shares = deal(inherited, cpus.len()).into_iter();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(cpus.len());
    let mut failure = None;
    for (index, &cpu) in cpus.iter().enumerate() {
        let (tx, rx) = mpsc::unbounded_channel();
        let initial = initial.clone();
        let ready = ready_tx.clone();
        let inherited = shares.next().unwrap_or_default();
        let spawned = std::thread::Builder::new()
            .name(format!("upstreamer-core-{index}"))
            .spawn(move || worker_main(index, cpu, rx, initial, inherited, hold, ready));
        match spawned {
            Ok(thread) => workers.push(Worker { thread, tx, cpu }),
            Err(e) => {
                failure = Some(StartError::Runtime(e));
                break;
            }
        }
    }
    drop(ready_tx);
    for _ in 0..workers.len() {
        let result = ready_rx.recv().unwrap_or_else(|_| {
            Err(StartError::Runtime(io::Error::other(
                "a core stopped during startup",
            )))
        });
        if let Err(e) = result {
            failure.get_or_insert(e);
        }
    }
    match failure {
        None => Ok(workers),
        Some(e) => {
            stop(workers, Instant::now());
            Err(e)
        }
    }
}

/// One share of `sockets` per core: the sockets of one address go to different cores, in
/// order, and those beyond the core count are closed (what is queued on them moves to the
/// address's other sockets where `net.ipv4.tcp_migrate_req` is on).
fn deal(sockets: Vec<Inherited>, cores: usize) -> Vec<Vec<Inherited>> {
    let mut shares: Vec<Vec<Inherited>> = (0..cores).map(|_| Vec::new()).collect();
    let mut dealt: Vec<(SocketKind, SocketAddr, usize)> = Vec::new();
    for socket in sockets {
        let key = (socket.transport, socket.addr);
        let at = match dealt.iter().position(|(t, a, _)| (*t, *a) == key) {
            Some(at) => at,
            None => {
                dealt.push((key.0, key.1, 0));
                dealt.len() - 1
            }
        };
        let next = dealt[at].2;
        dealt[at].2 += 1;
        if let Some(share) = shares.get_mut(next) {
            share.push(socket);
        }
    }
    shares
}

/// Drains every core with `deadline` and joins the threads.
pub(crate) fn stop(workers: Vec<Worker>, deadline: Instant) {
    retire(workers, Drain::stop(deadline));
}

/// Drains every core as `drain` says and joins the threads.
pub(crate) fn retire(workers: Vec<Worker>, drain: Drain) {
    start_drain(&workers, drain);
    join(workers);
}

/// Tells every core to drain.
pub(crate) fn start_drain(workers: &[Worker], drain: Drain) {
    for w in workers {
        let _ = w.tx.send(ToCore::Drain(drain.clone()));
    }
}

/// Waits until every core has drained.
pub(crate) fn join(workers: Vec<Worker>) {
    for w in workers {
        let _ = w.thread.join();
    }
}

/// A worker thread's body: pin, build the runtime, install, then run accept loops (one local
/// task per listener), the snapshot mailbox, the 1s clock and the pool sweeper.
fn worker_main(
    index: usize,
    cpu: usize,
    mut rx: mpsc::UnboundedReceiver<ToCore>,
    initial: Arc<Generation>,
    inherited: Vec<Inherited>,
    hold: Hold,
    ready: std::sync::mpsc::Sender<Result<(), StartError>>,
) {
    if let Err(e) = pin(cpu) {
        warning!("core {index}: cannot pin to cpu {cpu}: {e}");
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = ready.send(Err(StartError::Runtime(e)));
            return;
        }
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let core = Rc::new(Core::new(index, &initial));
        core.hold.set(hold);
        core.inherited.replace(inherited);
        if let Some(f) = core
            .sync_listeners(&core.snapshot())
            .await
            .into_iter()
            .next()
        {
            let _ = ready.send(Err(StartError::Bind {
                addr: f.addr,
                error: f.error,
            }));
            return;
        }
        drop(initial);
        let _ = ready.send(Ok(()));
        tokio::task::spawn_local(tick(core.clone()));
        tokio::task::spawn_local(sweep(core.clone()));
        tokio::task::spawn_local(crate::upstream::health::probe_loop(core.clone()));
        while let Some(msg) = rx.recv().await {
            match msg {
                ToCore::Install(generation, done) => {
                    let _ = done.send(core.install(&generation).await);
                }
                ToCore::Release(hold, done) => {
                    let _ = done.send(core.release(hold).await);
                }
                ToCore::Sockets(done) => {
                    let _ = done.send(core.sockets());
                }
                ToCore::Drain(drain) => {
                    core.drain(drain).await;
                    break;
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn pin(cpu: usize) -> io::Result<()> {
    // SAFETY: a zeroed cpu_set_t is the empty set; the size passed is the set's.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Other systems have no affinity API this crate uses; their threads float.
#[cfg(not(target_os = "linux"))]
fn pin(_cpu: usize) -> io::Result<()> {
    Ok(())
}

/// The CPUs this process may run on (systemd `CPUAffinity=`, cgroup cpusets, `taskset`).
pub(crate) fn allowed_cpus() -> Vec<usize> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: sched_getaffinity fills the set whose size is passed.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) == 0 {
                let cpus: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
                    .filter(|&c| libc::CPU_ISSET(c, &set))
                    .collect();
                if !cpus.is_empty() {
                    return cpus;
                }
            }
        }
    }
    let n = std::thread::available_parallelism().map_or(1, |n| n.get());
    (0..n).collect()
}

/// Refreshes the core's clock every second, writes the access log lines buffered since, and
/// publishes the core's metrics while its snapshot collects them.
async fn tick(core: Rc<Core>) {
    let mut every = tokio::time::interval(Duration::from_secs(1));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        every.tick().await;
        core.clock.tick();
        core.access.flush();
        let dropped = core.access.take_dropped();
        if dropped > 0 {
            warning!("core {}: {dropped} access log lines dropped", core.index);
        }
        if core.snapshot().metrics.is_some() {
            metrics::publish(&core);
        }
    }
}

/// Closes upstream connections idle past their origin's limit.
async fn sweep(core: Rc<Core>) {
    let mut every = tokio::time::interval(Duration::from_secs(5));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        every.tick().await;
        let snap = core.snapshot();
        if !snap.upstreams.origins().is_empty() {
            core.upstreams.sweep(&snap.upstreams, Instant::now());
        }
    }
}

/// Accept loop of one TCP listener: per connection, spawn_local(TLS accept -> h1|h2 driver) or
/// the h1 driver directly on cleartext listeners.
async fn accept_loop(core: Rc<Core>, listener: Listener) {
    let key = listener.key;
    loop {
        let (sock, remote) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                if out_of_resources(&e) {
                    // The queue keeps the connection; retrying at once would spin.
                    warning!("core {}: accept on {}: {e}", core.index, key.addr);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                } else {
                    debug!("core {}: accept on {}: {e}", core.index, key.addr);
                }
                continue;
            }
        };
        let info = ConnInfo {
            remote,
            local_port: key.addr.port(),
            scheme: match key.kind {
                ListenerKind::Https => Scheme::Https,
                ListenerKind::Http | ListenerKind::Quic => Scheme::Http,
            },
            proto: Proto::H1,
            listener: key,
        };
        let guard = core.track(key);
        tokio::task::spawn_local(connection(core.clone(), sock, info, guard));
    }
}

fn out_of_resources(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

/// The task of one accepted connection. Its future is what every open connection carries for
/// its whole life, so the handshake and the h2 driver are boxed: a task is as large as the
/// largest future it awaits inline.
#[expect(
    clippy::manual_async_fn,
    reason = "an async fn keeps a second copy of its arguments in its state"
)]
fn connection(
    core: Rc<Core>,
    sock: Socket,
    info: ConnInfo,
    guard: ConnGuard,
) -> impl std::future::Future<Output = ()> {
    async move {
        let (io, proto) = match info.scheme {
            Scheme::Http => (Transport::Plain(sock), Proto::H1),
            Scheme::Https => match Box::pin(handshake(&core, sock, info)).await {
                Some(accepted) => accepted,
                None => return,
            },
        };
        match proto {
            Proto::H2 => {
                let info = ConnInfo {
                    proto: Proto::H2,
                    ..info
                };
                Box::pin(crate::proto::h2::serve(core, io, info)).await;
            }
            _ => crate::proto::h1::server::serve(core, io, info).await,
        }
        // The connection counts as open until here (or until an early return drops the
        // future).
        drop(guard);
    }
}

/// TLS accept under the header timeout, with the protocol ALPN chose.
async fn handshake(core: &Core, sock: Socket, info: ConnInfo) -> Option<(Transport, Proto)> {
    let (config, timeout) = {
        let snap = core.snapshot();
        (snap.tls.clone()?, snap.plan.server.header_timeout)
    };
    let accepted = tls::accept_within(sock, config, timeout)
        .await
        .inspect_err(|e| debug!("core {}: TLS from {}: {e:?}", core.index, info.remote));
    core.connections.handshake(info.listener, accepted.is_ok());
    accepted.ok()
}

#[cfg(test)]
pub(crate) mod testing {
    //! Test support for the runtime: plans compiled from small configs, a blocking client,
    //! a per-thread allocation counter, and a record of what each core served.

    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::io::{Read, Write};
    use std::sync::{Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

    struct Counting;

    thread_local! {
        static ALLOCS: Cell<u64> = const { Cell::new(0) };
    }

    // SAFETY: forwards to the system allocator; the counter is a const thread-local without
    // a destructor, so touching it never allocates.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
            unsafe { System.realloc(ptr, layout, new_size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    /// Allocations made so far by the calling thread. The lib test binary has this one
    /// counting allocator; every allocation test reads its own thread's count from here.
    pub fn thread_allocations() -> u64 {
        ALLOCS.with(Cell::get)
    }

    /// Keeps counted sections and disruptive sections of tests apart. A counted section reads
    /// a thread's allocations or its timing and holds a read guard, so any number run at once.
    /// A disruptive section does something that would show in those counts on another
    /// thread, and holds the write guard:
    /// - raising a process signal. A signal wakes the signal driver of every runtime in the
    ///   process, and the first to wake broadcasts it on that thread. On macOS a broadcast can
    ///   allocate: the first one of each signal kind sets up the mutexes of tokio's watch
    ///   channel for it (`std`'s pthread mutexes are boxed on first lock), so a counted thread
    ///   would charge a test's signal to the requests it measures;
    /// - keeping every CPU busy, which starves the core threads a counted section waits on.
    static DISRUPTION: RwLock<()> = RwLock::new(());

    /// A counted section: no disruptive section runs until the guard drops.
    pub fn counted_section() -> RwLockReadGuard<'static, ()> {
        DISRUPTION.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// A counted section of a core's allocations, entered around one more request (`settle`)
    /// so the count the test starts from is read after it. A signal raised before the guard
    /// can be broadcast on the core thread after the core's previous request, and a count read
    /// from that request would charge the broadcast to the measured ones.
    pub fn counted_section_after(settle: impl FnOnce()) -> RwLockReadGuard<'static, ()> {
        let guard = counted_section();
        settle();
        guard
    }

    /// A disruptive section: waits until no counted section runs, and keeps them from starting
    /// until the guard drops.
    pub fn disruptive_section() -> RwLockWriteGuard<'static, ()> {
        DISRUPTION.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// What one core has answered on one listening port.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Served {
        pub requests: u64,
        /// Allocations the core's thread had made when it answered the latest request.
        pub allocations: u64,
        /// Access log writes the core had made by then.
        pub log_writes: u64,
    }

    /// By listening port and core index. Tests listen on ports of their own, so cores of
    /// tests that run at the same time never share an entry.
    static SERVED: Mutex<Vec<(u16, usize, Served)>> = Mutex::new(Vec::new());

    /// Called by the HTTP/1.1 driver for every request it answers, before the response is
    /// written.
    pub fn observe(core: &Core, info: &ConnInfo) {
        let allocations = thread_allocations();
        let log_writes = core.access.writes();
        let mut all = SERVED.lock().unwrap();
        let key = (info.local_port, core.index);
        match all.iter_mut().find(|(port, core, _)| (*port, *core) == key) {
            Some((_, _, served)) => {
                served.requests += 1;
                served.allocations = allocations;
                served.log_writes = log_writes;
            }
            None => all.push((
                key.0,
                key.1,
                Served {
                    requests: 1,
                    allocations,
                    log_writes,
                },
            )),
        }
    }

    /// What the core with index `core` has answered on `port`.
    pub fn served(port: u16, core: usize) -> Served {
        let all = SERVED.lock().unwrap();
        all.iter()
            .find(|(p, c, _)| (*p, *c) == (port, core))
            .map_or_else(Served::default, |(_, _, served)| *served)
    }

    /// A plan that listens on `addrs` and answers every host with `gen=NNNNNN\n`, its
    /// generation.
    pub fn plan(generation: u64, addrs: &[SocketAddr]) -> Plan {
        plan_from(
            generation,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": addrs, "https": [] },
                "sites": [{
                    "name": "test",
                    "hosts": ["*"],
                    "routes": [{ "respond": { "body": format!("gen={generation:06}\n") } }],
                }],
            }),
        )
    }

    /// The plan `config` compiles to.
    pub fn plan_from(generation: u64, config: &serde_json::Value) -> Plan {
        let config =
            crate::config::parse_config(crate::config::Format::Json, config.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("{}: {}", e.pointer, e.message))
                .value;
        let sources = crate::plan::compile::FileSystem;
        match crate::plan::compile::compile(&config, &sources, generation) {
            Ok((plan, _)) => plan,
            Err(diagnostics) => panic!("{diagnostics:?}"),
        }
    }

    pub fn generation(generation: u64, addrs: &[SocketAddr]) -> Arc<Generation> {
        Arc::new(Generation::standalone(
            plan(generation, addrs),
            None,
            Arc::default(),
        ))
    }

    /// A loopback address whose port was free a moment ago.
    pub fn free_addr() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// One response with a Content-Length, as (head, body). The connection must hold
    /// nothing after it.
    pub fn read_response(conn: &mut impl Read) -> io::Result<(String, Vec<u8>)> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_len = loop {
            if let Some(i) = memchr::memmem::find(&bytes, b"\r\n\r\n") {
                break i + 4;
            }
            match conn.read(&mut chunk)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => bytes.extend_from_slice(&chunk[..n]),
            }
        };
        let mut body = bytes.split_off(head_len);
        let head = String::from_utf8(bytes).expect("an ASCII head");
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .map_or(0, |v| v.parse().expect("a length"));
        assert!(body.len() <= length, "bytes after the response: {body:?}");
        let have = body.len();
        body.resize(length, 0);
        conn.read_exact(&mut body[have..])?;
        Ok((head, body))
    }

    /// One request on a keep-alive connection; returns the generation that answered it.
    pub fn get(conn: &mut std::net::TcpStream) -> io::Result<u64> {
        conn.write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")?;
        let (head, body) = read_response(conn)?;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        let body = std::str::from_utf8(&body).unwrap();
        Ok(body[4..10].parse().unwrap())
    }

    pub fn connect(addr: SocketAddr) -> std::net::TcpStream {
        let conn = std::net::TcpStream::connect(addr).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        conn
    }

    /// Whether a socket of this process listens on TCP `addr`: a stream socket bound to it
    /// without a peer (accepted connections have one). A connect cannot tell: with
    /// `SO_REUSEPORT`, any process of the same user (another test binary, say) may listen on
    /// the same port and accept it.
    pub fn listening_here(addr: SocketAddr) -> bool {
        let address = |fd, call: unsafe extern "C" fn(_, _, _) -> _| {
            // SAFETY: `try_init` hands a zeroed storage and its length to the call; a closed
            // fd only fails.
            unsafe {
                socket2::SockAddr::try_init(|storage, len| {
                    if call(fd, storage.cast(), len) == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error())
                    }
                })
            }
            .ok()
            .and_then(|(_, a)| a.as_socket())
        };
        // SAFETY: getdtablesize has no preconditions.
        let max = unsafe { libc::getdtablesize() };
        (0..max).any(|fd| {
            let mut kind: libc::c_int = 0;
            let mut len = size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: the option buffer and its length match; a closed fd only fails.
            let stream = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&raw mut kind).cast(),
                    &mut len,
                )
            } == 0
                && kind == libc::SOCK_STREAM;
            stream
                && address(fd, libc::getsockname) == Some(addr)
                && address(fd, libc::getpeername).is_none()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn output_size<A, B, C, D, R>(_: fn(A, B, C, D) -> R) -> usize {
        size_of::<R>()
    }

    #[test]
    fn an_idle_connection_task_stays_small() {
        // The connection future is the task state every open connection carries for its whole
        // life; the handshake, the h2 driver and the request path must not live in it inline.
        let size = output_size(connection);
        assert!(size <= 800, "connection future is {size} bytes");
    }

    #[test]
    fn imf_fixdate_matches_rfc_examples() {
        assert_eq!(&imf_fixdate(0), b"Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(&imf_fixdate(784_111_777), b"Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(&imf_fixdate(951_782_400), b"Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(
            &imf_fixdate(4_107_542_399),
            b"Sun, 28 Feb 2100 23:59:59 GMT"
        );
        assert_eq!(
            &imf_fixdate(1_798_761_599),
            b"Thu, 31 Dec 2026 23:59:59 GMT"
        );
    }

    #[test]
    fn clock_tracks_system_time() {
        let clock = Clock::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((clock.unix.get() - now).abs() <= 1);
        assert_eq!(*clock.http_date.borrow(), imf_fixdate(clock.unix.get()));
    }

    #[test]
    fn cores_share_one_port() {
        let cores = allowed_cpus().into_iter().take(4).collect::<Vec<_>>();
        let addr = free_addr();
        let workers = spawn_workers(&cores, generation(1, &[addr])).unwrap();
        for _ in 0..400 {
            assert_eq!(get(&mut connect(addr)).unwrap(), 1);
        }
        stop(workers, Instant::now());
        let per_core: Vec<u64> = (0..cores.len())
            .map(|core| served(addr.port(), core).requests)
            .collect();
        println!(
            "connections per core over {} cores: {per_core:?}",
            cores.len()
        );
        if cfg!(target_os = "linux") {
            assert!(
                per_core.iter().all(|&n| n > 0),
                "the kernel spreads connections over every core: {per_core:?}"
            );
        }
        assert_eq!(per_core.iter().sum::<u64>(), 400);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn each_core_thread_is_pinned_to_its_cpu() {
        let cpus = allowed_cpus().into_iter().rev().take(2).collect::<Vec<_>>();
        let workers = spawn_workers(&cpus, generation(1, &[free_addr()])).unwrap();
        // Other tests start and stop core threads meanwhile, on the first CPUs only, so threads
        // may vanish mid-scan and only this test's CPUs are checked.
        let mut allowed_lists = Vec::new();
        for task in std::fs::read_dir("/proc/self/task").unwrap() {
            let dir = task.unwrap().path();
            let read = |name| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
            if read("comm").trim() == "upstreamer-core" {
                let status = read("status");
                if let Some(list) = status
                    .lines()
                    .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                {
                    allowed_lists.push(list.trim().to_owned());
                }
            }
        }
        stop(workers, Instant::now());
        for cpu in cpus {
            assert!(
                allowed_lists.contains(&cpu.to_string()),
                "a core thread allowed only cpu {cpu}: {allowed_lists:?}"
            );
        }
    }

    #[test]
    fn bind_failure_is_a_start_failure() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        match spawn_workers(&[0, 0], generation(1, &[addr])) {
            Err(StartError::Bind { addr: failed, .. }) => assert_eq!(failed, addr),
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("bound a port another socket holds without SO_REUSEPORT"),
        }
    }

    #[test]
    fn zero_allocations_per_request_after_warm_up() {
        let addr = free_addr();
        let workers = spawn_workers(&[allowed_cpus()[0]], generation(7, &[addr])).unwrap();
        let mut conn = connect(addr);
        for _ in 0..2_000 {
            get(&mut conn).unwrap();
        }
        let counted = counted_section_after(|| {
            get(&mut conn).unwrap();
        });
        let before = served(addr.port(), 0).allocations;
        let requests = 20_000;
        for _ in 0..requests {
            assert_eq!(get(&mut conn).unwrap(), 7);
        }
        let after = served(addr.port(), 0).allocations;
        drop(counted);
        stop(workers, Instant::now());
        println!(
            "core thread allocations over {requests} keep-alive requests: {}",
            after - before
        );
        assert_eq!(after - before, 0, "allocations on the core thread");
    }

    #[test]
    fn a_logged_request_allocates_nothing_and_its_line_is_written_in_a_batch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let addr = free_addr();
        let plan = plan_from(
            9,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": [addr], "https": [] },
                "sites": [{
                    "name": "test",
                    "hosts": ["*"],
                    "accessLog": path,
                    "routes": [{ "respond": { "body": "gen=000009\n" } }],
                }],
            }),
        );
        let (files, failures) = access::Files::open(&plan.access_logs);
        assert!(failures.is_empty(), "{failures:?}");
        let generation = Arc::new(Generation::standalone(plan, None, Arc::new(files)));
        let workers = spawn_workers(&[allowed_cpus()[0]], generation).unwrap();
        let mut conn = connect(addr);
        let warm_up = 2_000;
        for _ in 1..warm_up {
            get(&mut conn).unwrap();
        }
        let counted = counted_section_after(|| {
            get(&mut conn).unwrap();
        });
        let before = served(addr.port(), 0);
        let requests = 20_000;
        for _ in 0..requests {
            assert_eq!(get(&mut conn).unwrap(), 9);
        }
        let after = served(addr.port(), 0);
        drop(counted);
        stop(workers, Instant::now());
        let allocations = after.allocations - before.allocations;
        let writes = after.log_writes - before.log_writes;
        println!("{requests} logged requests: {allocations} allocations, {writes} log writes");
        assert_eq!(allocations, 0, "allocations on the core thread");
        assert!(
            writes > 0 && writes * 50 <= requests,
            "{writes} writes for {requests} lines"
        );
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("a whole JSON line"))
            .collect();
        assert_eq!(
            lines.len() as u64,
            warm_up + requests,
            "written when the core stopped"
        );
        assert!(lines.iter().all(|l| l["status"] == 200 && l["bytes"] == 11));
    }

    /// Load for `strace -c -f` on Linux: one core, keep-alive requests from a blocking client.
    /// `UPSTREAMER_STRACE_REQUESTS` sets the count.
    #[test]
    #[ignore = "run under strace on Linux"]
    fn strace_load() {
        let requests: usize = std::env::var("UPSTREAMER_STRACE_REQUESTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        let addr = free_addr();
        let workers = spawn_workers(&[allowed_cpus()[0]], generation(1, &[addr])).unwrap();
        let mut conn = connect(addr);
        for _ in 0..requests {
            get(&mut conn).unwrap();
        }
        drop(conn);
        stop(workers, Instant::now());
        println!("served {requests} keep-alive requests");
    }

    #[test]
    fn install_swaps_snapshot_and_listeners_by_key() {
        let (a, b, c) = (free_addr(), free_addr(), free_addr());
        let workers = spawn_workers(&[0], generation(1, &[a, b])).unwrap();
        let mut on_a = connect(a);
        let mut on_b = connect(b);
        assert_eq!(get(&mut on_a).unwrap(), 1);
        assert_eq!(get(&mut on_b).unwrap(), 1);

        let install = |generation: Arc<Generation>| {
            let (done, failures) = oneshot::channel();
            workers[0]
                .tx
                .send(ToCore::Install(generation, done))
                .ok()
                .unwrap();
            failures.blocking_recv().unwrap()
        };
        assert!(install(super::testing::generation(2, &[b, c])).is_empty());

        assert!(
            std::net::TcpStream::connect(a).is_err(),
            "the removed listener is closed"
        );
        assert_eq!(get(&mut on_b).unwrap(), 2, "kept listener, next request");
        std::io::Write::write_all(&mut on_a, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").unwrap();
        let (head, _) = read_response(&mut on_a).unwrap();
        assert!(
            head.starts_with("HTTP/1.1 404 Not Found\r\n")
                && head.contains("\r\nconnection: close\r\n"),
            "the new plan has no site for a connection of the removed listener: {head}"
        );
        let mut rest = Vec::new();
        assert_eq!(
            std::io::Read::read_to_end(&mut on_a, &mut rest).unwrap(),
            0,
            "and the connection is closed"
        );
        assert_eq!(get(&mut connect(c)).unwrap(), 2, "added listener");

        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = taken.local_addr().unwrap();
        let failures = install(super::testing::generation(3, &[b, c, busy]));
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].addr, busy);
        assert_eq!(get(&mut on_b).unwrap(), 3, "other listeners keep serving");
        drop(taken);
        assert!(install(super::testing::generation(4, &[b, c, busy])).is_empty());
        assert_eq!(get(&mut connect(busy)).unwrap(), 4, "bound on retry");
        stop(workers, Instant::now());
    }

    #[test]
    fn a_held_listener_serves_nothing_until_released_then_what_queued_on_its_inherited_socket() {
        let inherited = Inherited::fresh(ListenerKind::Http);
        let addr = inherited.addr;
        let workers =
            spawn_workers_with(&[0], generation(1, &[addr]), vec![inherited], Hold::All).unwrap();
        fn ask<T>(worker: &Worker, message: impl FnOnce(oneshot::Sender<T>) -> ToCore) -> T {
            let (done, answer) = oneshot::channel();
            worker.tx.send(message(done)).ok().unwrap();
            answer.blocking_recv().unwrap()
        }
        let sockets = ask(&workers[0], ToCore::Sockets);
        assert_eq!(
            sockets.iter().map(|s| s.addr).collect::<Vec<_>>(),
            [addr],
            "a held socket is still one to hand on"
        );

        let mut early = connect(addr);
        std::io::Write::write_all(&mut early, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").unwrap();
        early
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let unanswered = read_response(&mut early).unwrap_err();
        assert!(
            matches!(
                unanswered.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "the connection waits in the socket's queue: {unanswered}"
        );

        let failures = ask(&workers[0], |done| ToCore::Release(Hold::Nothing, done));
        assert!(failures.is_empty(), "{failures:?}");
        early
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (head, body) = read_response(&mut early).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert_eq!(body, b"gen=000001\n", "the queued request is answered");
        assert_eq!(ask(&workers[0], ToCore::Sockets).len(), 1);
        stop(workers, Instant::now());
    }

    #[test]
    fn inherited_sockets_are_dealt_one_per_core_and_address() {
        let (first_a, first_b) = (
            Inherited::fresh(ListenerKind::Http),
            Inherited::fresh(ListenerKind::Http),
        );
        let (a, b) = (first_a.addr, first_b.addr);
        let more = |of: &Inherited| of.sibling(ListenerKind::Http);
        let sockets = vec![
            more(&first_a),
            more(&first_b),
            more(&first_a),
            first_a,
            first_b,
        ];
        let shares = deal(sockets, 2);
        let addrs: Vec<Vec<SocketAddr>> = shares
            .iter()
            .map(|share| share.iter().map(|s| s.addr).collect())
            .collect();
        assert_eq!(
            addrs,
            [vec![a, b], vec![a, b]],
            "each core gets one socket per address; the third socket of `a` has no core"
        );
        let alone = deal(vec![Inherited::fresh(ListenerKind::Http)], 2);
        assert!(alone[1].is_empty(), "a core without one binds its own");
    }

    #[test]
    fn an_idle_connection_outlives_the_start_of_a_drain_that_says_so() {
        let addr = free_addr();
        let workers = spawn_workers(&[0], generation(1, &[addr])).unwrap();
        let mut idle = connect(addr);
        get(&mut idle).unwrap();
        let now = Instant::now();
        let drain = Drain {
            deadline: now + Duration::from_secs(10),
            idle_close: now + Duration::from_millis(600),
            released: None,
        };
        let stopping = std::thread::spawn(move || retire(workers, drain));
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "the listener is closed"
        );
        std::io::Write::write_all(&mut idle, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").unwrap();
        let (head, body) = read_response(&mut idle).unwrap();
        assert!(
            head.starts_with("HTTP/1.1 200 OK\r\n") && head.contains("\r\nconnection: close\r\n"),
            "a request on an idle connection is answered, and the connection closed: {head}"
        );
        assert_eq!(body, b"gen=000001\n");
        stopping.join().unwrap();
        assert!(
            now.elapsed() < Duration::from_secs(5),
            "the drain ends with its last connection"
        );

        let workers = spawn_workers(&[0], generation(1, &[addr])).unwrap();
        let mut idle = connect(addr);
        get(&mut idle).unwrap();
        let now = Instant::now();
        let drain = Drain {
            deadline: now + Duration::from_secs(10),
            idle_close: now + Duration::from_millis(300),
            released: None,
        };
        retire(workers, drain);
        let waited = now.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(5),
            "a connection that stays idle is closed at `idle_close`: {waited:?}"
        );
        let mut rest = Vec::new();
        assert_eq!(std::io::Read::read_to_end(&mut idle, &mut rest).unwrap(), 0);
    }

    #[test]
    fn drain_closes_idle_connections_and_stops_accepting() {
        let addr = free_addr();
        let workers = spawn_workers(&[0], generation(1, &[addr])).unwrap();
        let mut idle = connect(addr);
        get(&mut idle).unwrap();
        let started = Instant::now();
        stop(workers, Instant::now() + Duration::from_secs(10));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "an idle connection does not hold the drain until the deadline"
        );
        let mut rest = Vec::new();
        assert_eq!(
            std::io::Read::read_to_end(&mut idle, &mut rest).unwrap(),
            0,
            "the idle connection is closed"
        );
        assert!(std::net::TcpStream::connect(addr).is_err());
    }

    #[test]
    fn drain_cuts_a_stuck_request_at_the_deadline() {
        let addr = free_addr();
        let workers = spawn_workers(&[0], generation(1, &[addr])).unwrap();
        let mut stuck = connect(addr);
        std::io::Write::write_all(&mut stuck, b"GET / HTTP/1.1\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        stop(workers, Instant::now() + Duration::from_millis(300));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(3),
            "a request in progress is waited for until the deadline, then cut: {waited:?}"
        );
    }

    #[test]
    fn regex_caches_follow_the_requested_plan() {
        let mut old = plan(1, &[free_addr()]);
        old.regexes = vec![regex_automata::meta::Regex::new("a(b)").unwrap()].into();
        let mut new = plan(2, &[free_addr()]);
        new.regexes = vec![
            regex_automata::meta::Regex::new("x").unwrap(),
            regex_automata::meta::Regex::new("(y)(z)").unwrap(),
        ]
        .into();
        let mut caches = RegexCaches::for_plan(&new);
        let input = regex_automata::Input::new("zab");
        let cache = caches.get(&old, RegexId(0));
        assert!(old.regexes[0].search_with(cache, &input).is_some());
        assert_eq!(caches.caches.len(), 1);
        caches.get(&new, RegexId(1));
        assert_eq!(caches.caches.len(), 2);
    }

    #[test]
    fn a_generation_with_the_same_plan_keeps_the_regex_caches_and_the_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("page.html");
        std::fs::write(&file, "x").unwrap();
        let root = dir.path().to_str().unwrap().as_bytes().to_vec();
        let config = |addr: SocketAddr| {
            serde_json::json!({
                "version": 1,
                "listen": { "http": [addr], "https": [] },
                "sites": [{
                    "name": "test",
                    "hosts": ["*"],
                    "routes": [{ "when": { "pathRegex": "^/(a)" }, "respond": { "body": "a" } }],
                }],
            })
        };
        let addr = free_addr();
        let first = Arc::new(Generation::standalone(
            plan_from(1, &config(addr)),
            None,
            Arc::default(),
        ));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio::task::LocalSet::new().block_on(&runtime, async {
            let core = Rc::new(Core::new(0, &first));
            assert!(core.install(&first).await.is_empty());
            core.regex.borrow_mut().get(&first.plan, RegexId(0));
            let caches = core.regex.borrow().caches.as_ptr();
            assert!(core.catalog.borrow_mut().probe(&root, b"page.html"));
            std::fs::remove_file(&file).unwrap();

            let epoch = Generation {
                upstreams: Registry::new(1).build(&first.plan),
                ..(*first).clone()
            };
            assert!(core.install(&epoch).await.is_empty());
            assert!(Arc::ptr_eq(&core.snapshot().upstreams, &epoch.upstreams));
            assert_eq!(
                core.regex.borrow().caches.as_ptr(),
                caches,
                "the same plan keeps its regex caches"
            );
            assert!(
                core.catalog.borrow_mut().probe(&root, b"page.html"),
                "and the catalog's entries"
            );

            let reload = Generation::standalone(plan_from(2, &config(addr)), None, Arc::default());
            assert!(core.install(&reload).await.is_empty());
            assert_ne!(
                core.regex.borrow().caches.as_ptr(),
                caches,
                "a new plan rebuilds them"
            );
            assert!(
                !core.catalog.borrow_mut().probe(&root, b"page.html"),
                "and drops mutable catalog entries"
            );
            core.drain(Drain::stop(Instant::now())).await;
        });
    }
}
