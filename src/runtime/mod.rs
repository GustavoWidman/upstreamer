//! Thread-per-core. One worker per CPU of the process's affinity mask, each pinned to its CPU,
//! each running a current-thread tokio runtime with a `LocalSet`. A core owns:
//! its listeners, its connections, its upstream pools, buffer and exchange pools, regex caches,
//! file catalog and coarse clock. It shares nothing mutable with other cores.
//!
//! The control thread (the process's main thread) owns the truth: it compiles plans, loads
//! certificates, rotates ticket keys, and publishes a [`Generation`] to every core over a
//! channel. A core installs it between requests: connections read [`Core::snapshot`] once per
//! request (an `Rc` clone, no atomic), so a reload takes effect on the next request of every
//! keep-alive connection, and an in-flight request finishes under the plan it started with.

pub(crate) mod control;

use crate::StartError;
use crate::access;
use crate::exchange::{ConnInfo, ExchangePool, Proto, Scheme};
use crate::files::catalog::Catalog;
use crate::log::{debug, warning};
use crate::net::buf::BufPool;
use crate::net::listen::{self, Listener};
use crate::net::{Socket, Transport};
use crate::plan::{ListenerKey, ListenerKind, Plan, RegexId, ServerParams};
use crate::proxy::pool::Pools;
use crate::tls::{self, CertStore, TicketKeys};
use std::cell::{Cell, RefCell};
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;

/// What the control thread publishes: immutable, shared by all cores.
pub(crate) struct Generation {
    pub plan: Arc<Plan>,
    /// Present exactly when the plan has a TLS or QUIC listener.
    pub tls: Option<TlsState>,
    /// The plan's access log files, opened for this generation.
    pub access: Arc<access::Files>,
}

/// Certificates and ticket keys of a generation. Ticket keys are shared by every core, so a
/// session ticket issued on one core resumes on another.
pub(crate) struct TlsState {
    pub certs: Arc<CertStore>,
    pub tickets: Arc<TicketKeys>,
}

/// A core's view of one generation, built on the core when the generation arrives (so the
/// rustls configs are this core's own).
pub(crate) struct CoreSnapshot {
    pub plan: Arc<Plan>,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub quic: Option<Arc<rustls::ServerConfig>>,
    pub access: Arc<access::Files>,
}

impl CoreSnapshot {
    fn new(generation: &Generation) -> CoreSnapshot {
        let plan = generation.plan.clone();
        let has = |kind| plan.listeners.iter().any(|l| l.key.kind == kind);
        let (tls, quic) = match &generation.tls {
            None => (None, None),
            Some(state) => (
                has(ListenerKind::Https)
                    .then(|| tls::server_config(state.certs.clone(), state.tickets.clone())),
                has(ListenerKind::Quic)
                    .then(|| tls::quic_server_config(state.certs.clone(), state.tickets.clone())),
            ),
        };
        CoreSnapshot {
            plan,
            tls,
            quic,
            access: generation.access.clone(),
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

/// Coarse clock: unix seconds and the formatted `Date` value, refreshed once per second by a
/// core-local timer (no `clock_gettime` or formatting per response).
pub(crate) struct Clock {
    pub unix: Cell<i64>,
    pub http_date: RefCell<[u8; 29]>,
    /// The system time and the monotonic time read together at the last tick, so a
    /// monotonic reading converts to wall time without another clock read.
    anchor: Cell<(Duration, Instant)>,
}

impl Clock {
    /// Reads the system clock now; the core's timer calls [`Clock::tick`] every second.
    pub fn new() -> Clock {
        let clock = Clock {
            unix: Cell::new(0),
            http_date: RefCell::new(*b"Thu, 01 Jan 1970 00:00:00 GMT"),
            anchor: Cell::new((Duration::ZERO, Instant::now())),
        };
        clock.tick();
        clock
    }
    /// Refreshes `unix` and `http_date` (IMF-fixdate) from the system clock.
    pub fn tick(&self) {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.anchor.set((wall, Instant::now()));
        let now = wall.as_secs() as i64;
        if now != self.unix.get() {
            self.unix.set(now);
            *self.http_date.borrow_mut() = imf_fixdate(now);
        }
    }
    /// The time since the Unix epoch at `at`, a monotonic reading taken after the last tick.
    pub fn wall(&self, at: Instant) -> Duration {
        let (wall, anchor) = self.anchor.get();
        wall + at.saturating_duration_since(anchor)
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
    /// The endpoint of a QUIC listener, kept to swap its TLS config at reload.
    quic: Option<quinn::Endpoint>,
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
    pub upstreams: Pools,
    pub clock: Clock,
    /// This core's access log buffers; written when the core drops.
    pub access: access::Writer,
    pub draining: Cell<bool>,
    /// Woken once, when draining starts.
    drain_started: Notify,
    /// Open downstream connections.
    conns: Cell<usize>,
    /// Woken when the last connection of a draining core ends.
    conns_closed: Notify,
    listeners: RefCell<Vec<Bound>>,
}

impl Core {
    /// A core for `generation` with no listener bound yet.
    fn new(index: usize, generation: &Generation) -> Core {
        Core {
            index,
            snapshot: RefCell::new(Rc::new(CoreSnapshot::new(generation))),
            regex: RefCell::new(RegexCaches::for_plan(&generation.plan)),
            catalog: RefCell::default(),
            bufs: BufPool::default(),
            exchanges: ExchangePool::default(),
            upstreams: Pools::default(),
            clock: Clock::new(),
            access: access::Writer::new(generation.access.clone()),
            draining: Cell::new(false),
            drain_started: Notify::new(),
            conns: Cell::new(0),
            conns_closed: Notify::new(),
            listeners: RefCell::default(),
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
    pub async fn install(self: &Rc<Self>, generation: &Generation) -> Vec<BindFailure> {
        let old = self.snapshot();
        let new = Rc::new(CoreSnapshot::new(generation));
        if !Arc::ptr_eq(&old.plan, &new.plan) {
            *self.regex.borrow_mut() = RegexCaches::for_plan(&new.plan);
            self.catalog.borrow_mut().retain_immutable();
            if !(old.plan.upstreams.is_empty() && new.plan.upstreams.is_empty()) {
                self.upstreams.adopt(&old.plan, &new.plan);
            }
        }
        self.access.adopt(&new.access);
        *self.snapshot.borrow_mut() = new.clone();
        self.sync_listeners(&new).await
    }
    /// Makes the bound listeners match the snapshot's plan, by key.
    async fn sync_listeners(self: &Rc<Self>, snap: &CoreSnapshot) -> Vec<BindFailure> {
        let wanted = &snap.plan.listeners;
        let (kept, gone): (Vec<Bound>, Vec<Bound>) = self
            .listeners
            .take()
            .into_iter()
            .partition(|b| wanted.iter().any(|l| l.key == b.key));
        close(gone).await;
        let mut bound = kept;
        let mut failures = Vec::new();
        for spec in wanted {
            match bound.iter().find(|b| b.key == spec.key) {
                Some(b) => {
                    if let (Some(endpoint), Some(config)) = (&b.quic, &snap.quic) {
                        match quic_config(config.clone(), &snap.plan.server) {
                            Ok(config) => endpoint.set_server_config(Some(config)),
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
        failures
    }
    fn listen(self: &Rc<Self>, key: ListenerKey, snap: &CoreSnapshot) -> io::Result<Bound> {
        let fd = listen::bind(key.addr, key.kind)?;
        match key.kind {
            ListenerKind::Http | ListenerKind::Https => {
                let listener = Listener::new(key, fd)?;
                let task = tokio::task::spawn_local(accept_loop(self.clone(), listener));
                Ok(Bound {
                    key,
                    task,
                    quic: None,
                })
            }
            ListenerKind::Quic => {
                let config = snap
                    .quic
                    .clone()
                    .ok_or_else(|| io::Error::other("QUIC listener without a TLS config"))?;
                let endpoint = listen::quic_endpoint(fd, quic_config(config, &snap.plan.server)?)?;
                let task =
                    tokio::task::spawn_local(quic_accept_loop(self.clone(), key, endpoint.clone()));
                Ok(Bound {
                    key,
                    task,
                    quic: Some(endpoint),
                })
            }
        }
    }
    /// Resolves once draining has started. Connections wait on it while idle.
    pub async fn until_drain(&self) {
        if !self.draining.get() {
            self.drain_started.notified().await;
        }
    }
    /// Counts a connection until the guard drops, so draining knows when the core is empty.
    fn track(self: &Rc<Self>) -> ConnGuard {
        self.conns.set(self.conns.get() + 1);
        ConnGuard { core: self.clone() }
    }
    /// Stops accepting, wakes idle connections so they close, and waits for the others to
    /// finish until `deadline`. Whatever is still open then is cut when the runtime drops.
    async fn drain(&self, deadline: Instant) {
        self.draining.set(true);
        self.drain_started.notify_waiters();
        let listeners = self.listeners.take();
        let endpoints: Vec<quinn::Endpoint> =
            listeners.iter().filter_map(|b| b.quic.clone()).collect();
        close(listeners).await;
        let deadline = tokio::time::Instant::from_std(deadline);
        while self.conns.get() > 0 {
            if tokio::time::timeout_at(deadline, self.conns_closed.notified())
                .await
                .is_err()
            {
                warning!(
                    "core {}: {} connections cut at the shutdown deadline",
                    self.index,
                    self.conns.get()
                );
                break;
            }
        }
        // The connections' closing packets go out while their endpoints still run. At the
        // deadline the connections still open are closed rather than dropped, so their clients
        // learn at once instead of after their idle timeout.
        for endpoint in endpoints {
            if tokio::time::timeout_at(deadline, endpoint.wait_idle())
                .await
                .is_err()
            {
                endpoint.close(H3_NO_ERROR, b"");
                let _ = tokio::time::timeout(CLOSE_GRACE, endpoint.wait_idle()).await;
            }
        }
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
        if let Some(endpoint) = &b.quic {
            endpoint.set_server_config(None);
        }
        b.task.abort();
        let _ = b.task.await;
    }
}

/// Accept loop of one QUIC endpoint: a local task per incoming connection.
async fn quic_accept_loop(core: Rc<Core>, key: ListenerKey, endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        let guard = core.track();
        let core = core.clone();
        tokio::task::spawn_local(async move {
            crate::proto::h3::serve(core, incoming, key).await;
            drop(guard);
        });
    }
}

struct ConnGuard {
    core: Rc<Core>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
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
    /// Stop accepting, GOAWAY/close idle, finish in-flight within `deadline`.
    Drain { deadline: Instant },
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
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(cpus.len());
    let mut failure = None;
    for (index, &cpu) in cpus.iter().enumerate() {
        let (tx, rx) = mpsc::unbounded_channel();
        let initial = initial.clone();
        let ready = ready_tx.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("upstreamer-core-{index}"))
            .spawn(move || worker_main(index, cpu, rx, initial, ready));
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

/// Drains every core with `deadline` and joins the threads.
pub(crate) fn stop(workers: Vec<Worker>, deadline: Instant) {
    for w in &workers {
        let _ = w.tx.send(ToCore::Drain { deadline });
    }
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
        while let Some(msg) = rx.recv().await {
            match msg {
                ToCore::Install(generation, done) => {
                    let _ = done.send(core.install(&generation).await);
                }
                ToCore::Drain { deadline } => {
                    core.drain(deadline).await;
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

/// Refreshes the core's clock every second, and writes the access log lines buffered since.
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
    }
}

/// Closes upstream connections idle past their origin's limit.
async fn sweep(core: Rc<Core>) {
    let mut every = tokio::time::interval(Duration::from_secs(5));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        every.tick().await;
        let snap = core.snapshot();
        if !snap.plan.upstreams.is_empty() {
            core.upstreams.sweep(&snap.plan, Instant::now());
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
        let guard = core.track();
        tokio::task::spawn_local(connection(core.clone(), sock, info, guard));
    }
}

fn out_of_resources(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

async fn connection(core: Rc<Core>, sock: Socket, info: ConnInfo, _guard: ConnGuard) {
    match info.scheme {
        Scheme::Http => crate::proto::h1::server::serve(core, Transport::Plain(sock), info).await,
        Scheme::Https => {
            let (config, timeout) = {
                let snap = core.snapshot();
                let Some(config) = snap.tls.clone() else {
                    return;
                };
                (config, snap.plan.server.header_timeout)
            };
            match tls::accept_within(sock, config, timeout).await {
                Ok((io, Proto::H2)) => {
                    let info = ConnInfo {
                        proto: Proto::H2,
                        ..info
                    };
                    crate::proto::h2::serve(core, io, info).await;
                }
                Ok((io, _)) => crate::proto::h1::server::serve(core, io, info).await,
                Err(e) => debug!("core {}: TLS from {}: {e:?}", core.index, info.remote),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Test support for the runtime: plans compiled from small configs, a blocking client,
    //! a per-thread allocation counter, and a record of what each core served.

    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::io::{Read, Write};
    use std::sync::Mutex;

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
        let config = crate::config::parse_config(config.to_string().as_bytes())
            .unwrap_or_else(|e| panic!("{}: {}", e.pointer, e.message));
        let sources = crate::plan::compile::FileSystem;
        match crate::plan::compile::compile(&config, &sources, generation) {
            Ok((plan, _)) => plan,
            Err(diagnostics) => panic!("{diagnostics:?}"),
        }
    }

    pub fn generation(generation: u64, addrs: &[SocketAddr]) -> Arc<Generation> {
        Arc::new(Generation {
            plan: Arc::new(plan(generation, addrs)),
            tls: None,
            access: Arc::default(),
        })
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
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

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
        let before = served(addr.port(), 0).allocations;
        let requests = 20_000;
        for _ in 0..requests {
            assert_eq!(get(&mut conn).unwrap(), 7);
        }
        let after = served(addr.port(), 0).allocations;
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
        let generation = Arc::new(Generation {
            plan: Arc::new(plan),
            tls: None,
            access: Arc::new(files),
        });
        let workers = spawn_workers(&[allowed_cpus()[0]], generation).unwrap();
        let mut conn = connect(addr);
        let warm_up = 2_000;
        for _ in 0..warm_up {
            get(&mut conn).unwrap();
        }
        let before = served(addr.port(), 0);
        let requests = 20_000;
        for _ in 0..requests {
            assert_eq!(get(&mut conn).unwrap(), 9);
        }
        let after = served(addr.port(), 0);
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
}
