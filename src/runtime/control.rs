//! The control thread: startup, reload, shutdown, systemd notification.
//!
//! systemd: `Type=notify-reload`. Startup sends `READY=1` after every core bound its
//! listeners. SIGHUP (sent by `systemctl reload`, by the NixOS switch when the config file
//! changed, and by ACME renewals through `reloadServices`) sends `RELOADING=1` +
//! `MONOTONIC_USEC`, rebuilds, publishes, waits until every core installed the generation, then
//! sends `READY=1`. SIGTERM and SIGINT drain.
//!
//! Reload is idempotent and never makes things worse: an unparsable or invalid config keeps
//! the running generation (logged, `STATUS=` set); certificate problems keep the previous
//! certificate per name. Running reload twice with the same inputs publishes an equivalent
//! generation.
//!
//! A SIGHUP that finds another program file at the path this one was started from hands over
//! to it instead ([`handover`]): a process of the new file takes the listening sockets, and
//! `MAINPID=` with `READY=1` moves the service's main process to it and ends the reload. This
//! process then drains like a stopping one, without a word to systemd, whose main process it
//! no longer is. A handover that fails is a failed reload: the running generation stays.
//!
//! Where systemd keeps a file descriptor store for the unit (`FileDescriptorStoreMax=`), the
//! listening sockets are kept in it ([`Stored`]): after a restart or a crash the next process
//! is given them back and serves what queued on them meanwhile, where it would otherwise bind
//! new sockets after a gap in which connections were refused.
//!
//! The control thread also keeps what outlives generations ([`Live`]): the upstream registry
//! (health cells, last discovered endpoints), the discovery feed, the metrics hub and the ACME
//! client. A generation is published one way, [`publish`], whatever caused it: a reload, a
//! ticket rotation, a discovery change or a certificate issued in process.

use super::handover::{self, Start};
use super::{BindFailure, Drain, Generation, Hold, START, TlsState, ToCore, Worker};
use crate::access::{self, OpenFailure};
use crate::acme;
use crate::discover::Feed;
use crate::limit::Limiters;
use crate::log::{error, info, warning};
use crate::metrics::{self, Hub};
use crate::net::listen::{Inherited, SocketKind};
use crate::plan::{Diagnostic, ListenerKind, Plan};
use crate::tls::{self, CertProblem, TicketKeys};
use crate::upstream::Registry;
use crate::{RunOptions, StartError};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal::unix::{SignalKind, signal};

/// How often session ticket keys rotate. The previous key still decrypts for one more period
/// and a ticket's lifetime is one period, so every ticket expires before its key is dropped.
const TICKET_ROTATION: Duration = Duration::from_secs(12 * 3600);
const TICKET_LIFETIME_SECS: u32 = TICKET_ROTATION.as_secs() as u32;

/// Produces the plan for a generation number: read, parse and compile the config.
pub(crate) type LoadPlan<'a> =
    dyn FnMut(u64) -> Result<(Plan, Vec<Diagnostic>), Vec<Diagnostic>> + 'a;

pub(crate) fn run(opts: RunOptions) -> Result<(), StartError> {
    crate::log::init();
    let path = opts.config;
    let start = Start::from_env().map_err(|e| StartError::Runtime(std::io::Error::other(e)))?;
    serve(
        &mut |generation| crate::plan::load(&path, generation),
        opts.workers,
        &Notifier::from_env(),
        start,
    )
}

/// What the control thread keeps across generations.
pub(crate) struct Live {
    pub registry: Registry,
    pub discovery: Feed,
    pub hub: Arc<Hub>,
    pub acme: acme::Manager,
    /// Ticket keys from the process this one took over from, for the first generation that
    /// serves TLS.
    tickets: Option<Arc<TicketKeys>>,
}

impl Live {
    pub fn new(cores: usize) -> Live {
        Live {
            registry: Registry::new(cores.min(usize::from(u16::MAX)) as u16),
            discovery: Feed::new(),
            hub: Hub::new(cores),
            acme: acme::Manager::new(),
            tickets: None,
        }
    }

    /// After a generation with a new plan is published: follow its discovery sources and
    /// issue its certificates.
    fn adopted(&mut self, generation: &Generation) {
        self.discovery.set_sources(&generation.plan);
        self.acme.set_plan(&generation.plan);
    }
}

/// Starts the cores, then serves signals until SIGTERM or SIGINT, or until it has handed over
/// to another process. Blocks the calling thread.
pub(crate) fn serve(
    load: &mut LoadPlan<'_>,
    workers: Option<u16>,
    notifier: &Notifier,
    start: Start,
) -> Result<(), StartError> {
    let Start {
        launch,
        sockets,
        tickets,
        mut predecessor,
    } = start;
    let mut stored = Stored::from_env(&sockets);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(StartError::Runtime)?;
    let served = runtime.block_on(async {
        // Handlers first: from READY=1 on, a SIGHUP must reload rather than kill.
        let mut hangup = signal(SignalKind::hangup()).map_err(StartError::Runtime)?;
        let mut terminate = signal(SignalKind::terminate()).map_err(StartError::Runtime)?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(StartError::Runtime)?;

        START.get_or_init(Instant::now);
        let mut generation = 1;
        let (plan, warnings) = load(generation).map_err(StartError::Config)?;
        let cpus = assign_cpus(workers.or(plan.workers));
        let mut live = Live::new(cpus.len());
        // An inherited key rotates when it would have where it came from.
        let mut rotated = Instant::now();
        if let Some((keys, age)) = tickets {
            live.tickets = Some(Arc::new(keys));
            rotated = rotated.checked_sub(age).unwrap_or(rotated);
        }
        let (current, problems) = assemble(plan, None, &mut live);
        report(&warnings, &problems);
        let mut current = Arc::new(current);
        live.hub.control().generation = generation;
        let hold = match predecessor {
            Some(_) => Hold::All,
            None => Hold::Nothing,
        };
        let workers = super::spawn_workers_with(&cpus, current.clone(), sockets, hold)?;
        live.discovery.set_sources(&current.plan);
        if predecessor.is_some() {
            // The process this one takes over from serves its sources' last endpoints; this
            // one takes over once it has its own.
            let Live {
                registry,
                discovery,
                ..
            } = &mut live;
            let reports = async || discovery.recv().await;
            let synced = first_reports(
                reports,
                &mut current,
                &workers,
                registry,
                DISCOVERY_PATIENCE,
            );
            if let Err(source) = synced.await {
                super::stop(workers, Instant::now());
                return Err(StartError::Runtime(std::io::Error::other(format!(
                    "discovery source {source} did not sync in {} s",
                    DISCOVERY_PATIENCE.as_secs()
                ))));
            }
        }
        if let Some(predecessor) = &mut predecessor {
            let promoted = match predecessor.ready() {
                Ok(()) => predecessor.promoted().await,
                Err(e) => Err(e),
            };
            if let Err(e) = promoted {
                super::stop(workers, Instant::now());
                return Err(StartError::Runtime(e));
            }
            log_bind_failures(&release(&workers, Hold::Quic).await);
        }
        let promoted = Instant::now();
        // Certificates are ordered by the main process alone: the validation requests of an
        // order reach whichever process accepts them.
        live.acme.set_plan(&current.plan);
        crate::discover::publish(&live.registry, &live.hub);
        info!(
            "serving generation {generation} on {} cores, {} listeners",
            workers.len(),
            current.plan.listeners.len()
        );
        notifier.notify(&format!("READY=1\nSTATUS={}", status_line(&current, &live)));
        stored.sync(&workers, notifier).await;

        let next_rotation = (rotated + TICKET_ROTATION).max(Instant::now());
        let mut rotate = tokio::time::interval_at(
            tokio::time::Instant::from_std(next_rotation),
            TICKET_ROTATION,
        );
        let handed_over = loop {
            tokio::select! {
                _ = hangup.recv() => {
                    generation += 1;
                    if let Some(launch) = launch.as_ref().filter(|launch| launch.replaced()) {
                        notifier.notify(&format!(
                            "RELOADING=1\nMONOTONIC_USEC={}",
                            monotonic_usec()
                        ));
                        let tickets = current
                            .tls
                            .as_ref()
                            .map(|tls| handover::Tickets::of(&tls.tickets, rotated.elapsed()));
                        let offered = tokio::select! {
                            offered = hand_over(launch, &workers, tickets) => offered,
                            // The offer is dropped, and its process killed with it.
                            _ = terminate.recv() => break None,
                            _ = interrupt.recv() => break None,
                        };
                        // The successor is the main process from this notification on, and
                        // the byte it waits for tells it so. A successor that died meanwhile
                        // is no main process (systemd refuses a process that is gone, and
                        // treats one that goes as the service failing), and this process goes
                        // on serving.
                        let refused = match offered {
                            Ok(successor) => {
                                let pid = successor.pid;
                                notifier.notify(&format!("MAINPID={pid}\nREADY=1"));
                                match successor.promote() {
                                    Ok(released) => break Some((pid, released)),
                                    Err(e) => format!("it went away as it took over: {e}"),
                                }
                            }
                            Err(reason) => reason,
                        };
                        live.hub.control().reloads_rejected += 1;
                        let reason = format!(
                            "cannot hand over to {}: {}",
                            launch.path().display(),
                            refused.replace('\n', " ")
                        );
                        error!("reload rejected: {reason}");
                        notifier.notify(&format!(
                            "READY=1\nSTATUS=reload failed, still serving generation {}: {reason}",
                            current.plan.generation
                        ));
                        continue;
                    }
                    reload(load, &mut current, generation, &workers, notifier, &mut live).await;
                    stored.sync(&workers, notifier).await;
                }
                _ = rotate.tick() => {
                    rotated = Instant::now();
                    if let Some(tls) = &current.tls {
                        let next = Arc::new(Generation {
                            tls: Some(TlsState {
                                certs: tls.certs.clone(),
                                tickets: Arc::new(tls.tickets.rotated()),
                            }),
                            ..(*current).clone()
                        });
                        log_bind_failures(&publish(&workers, next.clone()).await);
                        current = next;
                    }
                }
                found = live.discovery.recv() => {
                    discovered(found, &mut current, &workers, &mut live.registry).await;
                    crate::discover::publish(&live.registry, &live.hub);
                    notifier.notify(&format!("STATUS={}", status_line(&current, &live)));
                }
                event = live.acme.recv() => match event {
                    acme::Event::Issued => {
                        if let Some(next) = reload_certificates(&current) {
                            let next = Arc::new(next);
                            log_bind_failures(&publish(&workers, next.clone()).await);
                            current = next;
                        }
                    }
                },
                () = released(&mut predecessor) => {
                    predecessor = None;
                    log_bind_failures(&release(&workers, Hold::Nothing).await);
                    if current.plan.listeners.iter().any(|l| l.key.kind == ListenerKind::Quic) {
                        info!(
                            "serving QUIC: the previous process let go of the UDP sockets after \
                             {} ms",
                            promoted.elapsed().as_millis()
                        );
                    }
                    stored.sync(&workers, notifier).await;
                }
                _ = terminate.recv() => break None,
                _ = interrupt.recv() => break None,
            }
        };
        let grace = current.plan.server.shutdown;
        match handed_over {
            None => shutdown(workers, grace, notifier),
            Some((pid, released)) => {
                // Discovery and certificate orders are the successor's from here on.
                drop(live);
                info!(
                    "handed over to process {pid}; draining, at most {} ms",
                    grace.as_millis()
                );
                retire(workers, grace, released, &mut predecessor).await;
            }
        }
        Ok(())
    });
    if let (Err(e), Some(predecessor)) = (&served, &mut predecessor) {
        predecessor.failed(&e.to_string());
    }
    served
}

/// A discovery source reported: publishes the plan with the source's endpoints when they
/// changed.
async fn discovered(
    found: crate::discover::Found,
    current: &mut Arc<Generation>,
    workers: &[Worker],
    registry: &mut Registry,
) {
    if let Some(upstreams) = registry.discovered(&current.plan, found) {
        // The same plan `Arc`: cores keep their regex caches and file catalog and re-index
        // their origin slots by identity.
        let metrics = current.metrics.as_ref().map(|(_, hub)| {
            (
                metrics::Layout::build(&current.plan, &upstreams),
                hub.clone(),
            )
        });
        let next = Arc::new(Generation {
            upstreams,
            metrics,
            ..(**current).clone()
        });
        log_bind_failures(&publish(workers, next.clone()).await);
        *current = next;
    }
}

/// How long a process that takes over from another waits for its discovery sources.
const DISCOVERY_PATIENCE: Duration = Duration::from_secs(10);

/// Applies discovery reports until every source of the plan has synced. An error names a
/// source that has not after `patience`.
async fn first_reports(
    mut next: impl AsyncFnMut() -> crate::discover::Found,
    current: &mut Arc<Generation>,
    workers: &[Worker],
    registry: &mut Registry,
    patience: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + patience;
    loop {
        let unsynced = registry
            .sources()
            .find(|(_, endpoints)| !endpoints.synced())
            .map(|(source, _)| source.label());
        let Some(unsynced) = unsynced else {
            return Ok(());
        };
        match tokio::time::timeout_at(deadline, next()).await {
            Ok(found) => discovered(found, current, workers, registry).await,
            Err(_) => return Err(unsynced),
        }
    }
}

/// Resolves once the process this one took over from reads the UDP sockets no more. Pending
/// forever without such a process.
async fn released(predecessor: &mut Option<handover::Predecessor>) {
    match predecessor {
        Some(predecessor) => predecessor.released().await,
        None => std::future::pending().await,
    }
}

/// Starts the program at `launch` with every core's listening sockets and waits until it is
/// ready to serve them.
async fn hand_over(
    launch: &handover::Launch,
    workers: &[Worker],
    tickets: Option<handover::Tickets>,
) -> Result<handover::Successor, String> {
    let sockets = sockets(workers).await;
    handover::offer(launch, sockets, tickets, handover::READY_TIMEOUT).await
}

/// The end of a process that handed over: every core drains, without a word to systemd, whose
/// main process this no longer is. Idle keep-alive connections stay open for half the grace,
/// since nothing waits for this process to exit and a request that arrives on one is then
/// answered instead of meeting a closed connection.
///
/// `released` is this process's end of the handover pipe: the successor reads the UDP sockets
/// once every copy is closed. Each core drops its copy when it reads none any more. A process
/// that hands over while its own predecessor still reads them keeps one until that let go.
async fn retire(
    workers: Vec<Worker>,
    grace: Duration,
    released: Arc<std::os::fd::OwnedFd>,
    predecessor: &mut Option<handover::Predecessor>,
) {
    let now = Instant::now();
    let drain = Drain {
        deadline: now + grace,
        idle_close: now + grace / 2,
        released: Some(released.clone()),
    };
    let deadline = tokio::time::Instant::from_std(drain.deadline);
    super::start_drain(&workers, drain);
    if let Some(predecessor) = predecessor {
        let _ = tokio::time::timeout_at(deadline, predecessor.released()).await;
    }
    drop(released);
    super::join(workers);
}

/// A descriptor of every listening socket, each core's in core order.
async fn sockets(workers: &[Worker]) -> Vec<Inherited> {
    let mut pending = Vec::with_capacity(workers.len());
    for w in workers {
        let (done, report) = tokio::sync::oneshot::channel();
        if w.tx.send(ToCore::Sockets(done)).is_ok() {
            pending.push(report);
        }
    }
    let mut sockets = Vec::new();
    for report in pending {
        sockets.extend(report.await.unwrap_or_default());
    }
    sockets
}

/// The listening sockets in the service manager's file descriptor store, by name: one name
/// per address, shared by the sockets of every core.
struct Stored {
    /// Whether the service manager keeps a store for this service (`$FDSTORE`).
    enabled: bool,
    /// The names that may be in the store, each with how many sockets it may hold.
    names: Vec<(String, usize)>,
}

impl Stored {
    /// `inherited` are the sockets this process was given: the store held them, or the process
    /// this one takes over from did, which stored them too.
    fn from_env(inherited: &[Inherited]) -> Stored {
        Stored {
            enabled: std::env::var_os("FDSTORE").is_some(),
            names: Stored::count(inherited),
        }
    }

    /// `tcp_0.0.0.0_80`, `udp_[__]_443`: a name may not hold a colon.
    fn name(socket: &Inherited) -> String {
        let kind = match socket.transport {
            SocketKind::Tcp => "tcp",
            SocketKind::Udp => "udp",
        };
        format!("{kind}_{}", socket.addr).replace(':', "_")
    }

    /// The names of `sockets`, sorted, each with the number of its sockets.
    fn count(sockets: &[Inherited]) -> Vec<(String, usize)> {
        let mut names: Vec<(String, usize)> = Vec::new();
        for name in sockets.iter().map(Stored::name) {
            match names.iter_mut().find(|(known, _)| *known == name) {
                Some((_, count)) => *count += 1,
                None => names.push((name, 1)),
            }
        }
        names.sort();
        names
    }

    /// Makes the store hold the listening sockets of the cores, and no other: a socket left
    /// in the store that no core accepts on would keep taking connections nobody serves.
    /// Sockets are stored again each time (the service manager keeps one descriptor of a
    /// socket it already has). A name is removed first when no listener has it any more, or
    /// when it may hold more sockets than the cores have now, as after a start with fewer
    /// cores than the process before.
    async fn sync(&mut self, workers: &[Worker], notifier: &Notifier) {
        if !self.enabled {
            return;
        }
        let sockets = sockets(workers).await;
        let serving = Stored::count(&sockets);
        for (name, known) in &self.names {
            let now = serving
                .iter()
                .find(|(n, _)| n == name)
                .map_or(0, |(_, n)| *n);
            if now < *known {
                notifier.notify(&format!("FDSTOREREMOVE=1\nFDNAME={name}"));
            }
        }
        for (name, _) in &serving {
            let fds: Vec<RawFd> = sockets
                .iter()
                .filter(|socket| &Stored::name(socket) == name)
                .map(|socket| socket.fd.as_raw_fd())
                .collect();
            for fds in fds.chunks(Notifier::MAX_FDS) {
                notifier.notify_with_fds(&format!("FDSTORE=1\nFDNAME={name}"), fds);
            }
        }
        self.names = serving;
    }
}

/// Narrows every core's hold and waits until each serves what it no longer covers. Returns the
/// listeners that could not be bound, once per address.
async fn release(workers: &[Worker], hold: Hold) -> Vec<BindFailure> {
    let mut pending = Vec::with_capacity(workers.len());
    for w in workers {
        let (done, report) = tokio::sync::oneshot::channel();
        if w.tx.send(ToCore::Release(hold, done)).is_ok() {
            pending.push(report);
        }
    }
    collect(pending).await
}

async fn reload(
    load: &mut LoadPlan<'_>,
    current: &mut Arc<Generation>,
    generation: u64,
    workers: &[Worker],
    notifier: &Notifier,
    live: &mut Live,
) {
    notifier.notify(&format!("RELOADING=1\nMONOTONIC_USEC={}", monotonic_usec()));
    let status = match rebuild(load, Some(current), generation, live) {
        Ok((next, warnings, problems)) => {
            report(&warnings, &problems);
            let next = Arc::new(next);
            let failures = publish(workers, next.clone()).await;
            log_bind_failures(&failures);
            if next.plan.workers != current.plan.workers {
                warning!("a changed worker count applies at the next restart");
            }
            *current = next;
            live.adopted(current);
            crate::discover::publish(&live.registry, &live.hub);
            {
                let mut control = live.hub.control();
                control.generation = generation;
                control.reloads_ok += 1;
            }
            info!("serving generation {generation}");
            let mut status = status_line(current, live);
            if let Some(f) = failures.first() {
                status.push_str(&format!("; cannot bind {}: {}", f.addr, f.error));
            }
            if let Some(f) = problems.logs.first() {
                status.push_str(&format!(
                    "; cannot open access log {}: {}",
                    f.path.display(),
                    f.error
                ));
            }
            status
        }
        Err(diagnostics) => {
            live.hub.control().reloads_rejected += 1;
            for d in &diagnostics {
                error!("reload rejected: {d}");
            }
            let first = diagnostics
                .iter()
                .find(|d| d.is_error())
                .or(diagnostics.first());
            let reason = first.map_or_else(String::new, |d| d.to_string().replace('\n', " "));
            format!(
                "reload failed, still serving generation {}: {reason}",
                current.plan.generation
            )
        }
    };
    notifier.notify(&format!("READY=1\nSTATUS={status}"));
}

/// What a generation was built with although part of it failed: certificates kept from the
/// previous generation or made up, and access logs that could not be opened.
pub(crate) struct Problems {
    pub certs: Vec<CertProblem>,
    pub logs: Vec<OpenFailure>,
}

/// Builds the next generation from disk, opening every access log file anew. `Err` keeps the
/// current one and changes nothing in `live`.
pub(crate) fn rebuild(
    load: &mut LoadPlan<'_>,
    current: Option<&Generation>,
    generation: u64,
    live: &mut Live,
) -> Result<(Generation, Vec<Diagnostic>, Problems), Vec<Diagnostic>> {
    let (plan, warnings) = load(generation)?;
    let (next, problems) = assemble(plan, current, live);
    Ok((next, warnings, problems))
}

/// The generation of a compiled plan: certificates (the previous one kept per name on a
/// problem), the upstream table (health carried by identity), limit tables carried by spec,
/// metrics when the plan collects them, and the plan's access log files opened anew.
fn assemble(plan: Plan, current: Option<&Generation>, live: &mut Live) -> (Generation, Problems) {
    let previous = current.and_then(|g| g.tls.as_ref());
    let acme = live.acme.challenges(&plan);
    let (tls, problems) = if plan
        .listeners
        .iter()
        .any(|l| l.key.kind != ListenerKind::Http)
    {
        let (mut certs, problems) = tls::load(&plan.certs, previous.map(|t| &*t.certs));
        certs.acme = acme.clone();
        let tickets = match (previous, live.tickets.take()) {
            (Some(previous), _) => previous.tickets.clone(),
            (None, Some(inherited)) => inherited,
            (None, None) => Arc::new(TicketKeys::generate(TICKET_LIFETIME_SECS)),
        };
        let certs = Arc::new(certs);
        (Some(TlsState { certs, tickets }), problems)
    } else {
        (None, Vec::new())
    };
    let (files, logs) = access::Files::open(&plan.access_logs);
    let upstreams = live.registry.build(&plan);
    let limits = Limiters::carry(&plan, current.map(|g| (&*g.plan, &*g.limits)));
    let metrics = plan
        .metrics
        .then(|| (metrics::Layout::build(&plan, &upstreams), live.hub.clone()));
    let next = Generation {
        plan: Arc::new(plan),
        upstreams,
        limits,
        metrics,
        acme,
        tls,
        access: Arc::new(files),
    };
    (
        next,
        Problems {
            certs: problems,
            logs,
        },
    )
}

/// The current generation with its certificates read again (the ACME client wrote new ones).
/// `None` when it serves no TLS.
fn reload_certificates(current: &Generation) -> Option<Generation> {
    let tls = current.tls.as_ref()?;
    let (mut certs, problems) = tls::load(&current.plan.certs, Some(&tls.certs));
    certs.acme = current.acme.clone();
    report(
        &[],
        &Problems {
            certs: problems,
            logs: Vec::new(),
        },
    );
    Some(Generation {
        tls: Some(TlsState {
            certs: Arc::new(certs),
            tickets: tls.tickets.clone(),
        }),
        ..current.clone()
    })
}

/// `serving generation N`, and what is wrong with the discovery sources.
fn status_line(current: &Generation, live: &Live) -> String {
    let mut status = format!("serving generation {}", current.plan.generation);
    crate::discover::status(&live.registry, &mut status);
    status
}

fn report(warnings: &[Diagnostic], problems: &Problems) {
    for w in warnings {
        warning!("{w}");
    }
    for f in &problems.logs {
        warning!(
            "access log {}: {}; its lines are dropped until a reload opens it",
            f.path.display(),
            f.error
        );
    }
    for p in &problems.certs {
        warning!(
            "certificate {}: {}; previous certificate kept for {:?}, self-signed for {:?}",
            p.source,
            p.message,
            p.kept_previous,
            p.self_signed
        );
    }
}

fn log_bind_failures(failures: &[BindFailure]) {
    for f in failures {
        error!("cannot bind {}: {}", f.addr, f.error);
    }
}

/// The CPUs to start one core on each: the affinity mask, or `workers` of them (wrapping
/// around when there are more workers than CPUs).
fn assign_cpus(workers: Option<u16>) -> Vec<usize> {
    let allowed = super::allowed_cpus();
    let n = workers.map_or(allowed.len(), usize::from).max(1);
    allowed.iter().copied().cycle().take(n).collect()
}

/// Sends the generation to every core and waits until each installed it. Returns the
/// listeners that could not be bound, once per address.
pub(crate) async fn publish(workers: &[Worker], generation: Arc<Generation>) -> Vec<BindFailure> {
    let mut pending = Vec::with_capacity(workers.len());
    for w in workers {
        let (done, report) = tokio::sync::oneshot::channel();
        if w.tx.send(ToCore::Install(generation.clone(), done)).is_ok() {
            pending.push(report);
        }
    }
    collect(pending).await
}

/// Every core's bind failures, once per address.
async fn collect(
    pending: Vec<tokio::sync::oneshot::Receiver<Vec<BindFailure>>>,
) -> Vec<BindFailure> {
    let mut failures: Vec<BindFailure> = Vec::new();
    for report in pending {
        for f in report.await.unwrap_or_default() {
            if !failures.iter().any(|seen| seen.addr == f.addr) {
                failures.push(f);
            }
        }
    }
    failures
}

/// SIGTERM: `STOPPING=1`, drain every core with the shutdown deadline, join threads.
pub(crate) fn shutdown(workers: Vec<Worker>, grace: Duration, notifier: &Notifier) {
    notifier.notify("STOPPING=1");
    info!("draining, at most {} ms", grace.as_millis());
    super::stop(workers, Instant::now() + grace);
}

/// `$NOTIFY_SOCKET`, read once at startup.
pub(crate) struct Notifier {
    target: Option<(UnixDatagram, NotifyAddr)>,
}

enum NotifyAddr {
    Path(PathBuf),
    #[cfg(target_os = "linux")]
    Abstract(std::os::unix::net::SocketAddr),
}

impl Notifier {
    /// The socket systemd named in `NOTIFY_SOCKET`; without it, notifications are dropped.
    pub fn from_env() -> Notifier {
        let Some(value) = std::env::var_os("NOTIFY_SOCKET") else {
            return Notifier { target: None };
        };
        let bytes = value.as_encoded_bytes();
        let addr = match bytes.strip_prefix(b"@") {
            #[cfg(target_os = "linux")]
            Some(name) => {
                use std::os::linux::net::SocketAddrExt;
                match std::os::unix::net::SocketAddr::from_abstract_name(name) {
                    Ok(addr) => NotifyAddr::Abstract(addr),
                    Err(e) => {
                        warning!("NOTIFY_SOCKET: {e}");
                        return Notifier { target: None };
                    }
                }
            }
            _ => NotifyAddr::Path(PathBuf::from(value)),
        };
        Notifier::to(addr)
    }
    /// Notifications to a datagram socket bound at `path`.
    pub fn to_path(path: PathBuf) -> Notifier {
        Notifier::to(NotifyAddr::Path(path))
    }
    fn to(addr: NotifyAddr) -> Notifier {
        match UnixDatagram::unbound() {
            Ok(sock) => Notifier {
                target: Some((sock, addr)),
            },
            Err(e) => {
                warning!("NOTIFY_SOCKET: {e}");
                Notifier { target: None }
            }
        }
    }
    /// Sends one notification (newline-separated `KEY=value` assignments).
    pub fn notify(&self, state: &str) {
        let Some((sock, addr)) = &self.target else {
            return;
        };
        let sent = match addr {
            NotifyAddr::Path(path) => sock.send_to(state.as_bytes(), path),
            #[cfg(target_os = "linux")]
            NotifyAddr::Abstract(addr) => sock.send_to_addr(state.as_bytes(), addr),
        };
        if let Err(e) = sent {
            warning!("sd_notify: {e}");
        }
    }

    /// The most descriptors one notification carries: under the kernel's limit per message.
    pub const MAX_FDS: usize = 128;

    /// Sends one notification with descriptors attached (`SCM_RIGHTS`), at most
    /// [`Notifier::MAX_FDS`] of them. The receiver gets descriptors of its own.
    pub fn notify_with_fds(&self, state: &str, fds: &[RawFd]) {
        let Some((sock, addr)) = &self.target else {
            return;
        };
        let addr = match addr {
            NotifyAddr::Path(path) => socket2::SockAddr::unix(path),
            #[cfg(target_os = "linux")]
            NotifyAddr::Abstract(addr) => {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::ffi::OsStrExt;
                // The address of an abstract socket is its name after a zero byte.
                let mut name = vec![0u8];
                name.extend_from_slice(addr.as_abstract_name().unwrap_or_default());
                socket2::SockAddr::unix(std::ffi::OsStr::from_bytes(&name))
            }
        };
        let sent = addr.and_then(|addr| {
            let control = rights(fds);
            let buffers = [std::io::IoSlice::new(state.as_bytes())];
            let message = socket2::MsgHdr::new()
                .with_addr(&addr)
                .with_buffers(&buffers)
                .with_control(&control);
            socket2::SockRef::from(sock).sendmsg(&message, 0)
        });
        if let Err(e) = sent {
            warning!("sd_notify: {e}");
        }
    }
}

/// The control message that passes `fds` over a Unix socket.
fn rights(fds: &[RawFd]) -> Vec<u8> {
    let bytes = size_of_val(fds);
    // SAFETY: CMSG_SPACE and CMSG_LEN compute sizes from a length. The buffer is CMSG_SPACE
    // bytes, which holds one header and `bytes` of data; the header is written unaligned, and
    // CMSG_DATA of a header at the start of the buffer points `bytes` before its end.
    unsafe {
        let mut control = vec![0u8; libc::CMSG_SPACE(bytes as u32) as usize];
        let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
        let mut filled: libc::cmsghdr = std::mem::zeroed();
        filled.cmsg_level = libc::SOL_SOCKET;
        filled.cmsg_type = libc::SCM_RIGHTS;
        filled.cmsg_len = libc::CMSG_LEN(bytes as u32) as _;
        header.write_unaligned(filled);
        std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(header), bytes);
        control
    }
}

/// `CLOCK_MONOTONIC` in microseconds, the clock systemd compares `MONOTONIC_USEC` with.
fn monotonic_usec() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::testing::{
        connect, disruptive_section, free_addr, get, listening_here, plan, read_response,
    };
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn listen_notify() -> (tempfile::TempDir, PathBuf, UnixDatagram) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let sock = UnixDatagram::bind(&path).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        (dir, path, sock)
    }

    /// The next datagram. A signal the lifecycle test raises is handled on whichever thread
    /// the kernel picks, and one blocked in a receive with a timeout is interrupted by it.
    fn recv(sock: &UnixDatagram) -> String {
        let mut buf = [0u8; 4096];
        let n = loop {
            match sock.recv(&mut buf) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                received => break received.expect("a notification"),
            }
        };
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    fn signal(sig: libc::c_int) {
        // SAFETY: sends a signal to this process, whose handler the control loop installed.
        assert_eq!(unsafe { libc::kill(libc::getpid(), sig) }, 0);
    }

    #[test]
    fn notifier_writes_datagrams() {
        let (_dir, path, sock) = listen_notify();
        Notifier::to_path(path).notify("READY=1\nSTATUS=x");
        assert_eq!(recv(&sock), "READY=1\nSTATUS=x");
        Notifier { target: None }.notify("READY=1");
    }

    /// Receives one datagram with the descriptors attached to it.
    fn recv_with_fds(sock: &UnixDatagram) -> (String, Vec<std::os::fd::OwnedFd>) {
        use std::os::fd::FromRawFd;
        let mut text = [0u8; 4096];
        let mut control = [0u64; 128];
        let mut iov = libc::iovec {
            iov_base: text.as_mut_ptr().cast(),
            iov_len: text.len(),
        };
        // SAFETY: the message header points at the two buffers above, with their sizes, for
        // the duration of the call; every descriptor the kernel put into the control buffer
        // is new and owned by nothing else.
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of_val(&control) as _;
            let n = loop {
                let n = libc::recvmsg(sock.as_raw_fd(), &mut message, 0);
                let interrupted =
                    || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
                if n >= 0 || !interrupted() {
                    break n;
                }
            };
            assert!(n >= 0, "{}", std::io::Error::last_os_error());
            let mut fds = Vec::new();
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let bytes = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let data = libc::CMSG_DATA(header).cast::<RawFd>();
                    for i in 0..bytes / size_of::<RawFd>() {
                        fds.push(std::os::fd::OwnedFd::from_raw_fd(
                            data.add(i).read_unaligned(),
                        ));
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
            (String::from_utf8(text[..n as usize].to_vec()).unwrap(), fds)
        }
    }

    #[test]
    fn a_notification_carries_descriptors_to_the_receiver() {
        use crate::plan::ListenerKind;
        let (_dir, path, sock) = listen_notify();
        let sent = [
            Inherited::fresh(ListenerKind::Http),
            Inherited::fresh(ListenerKind::Quic),
        ];
        let fds: Vec<RawFd> = sent.iter().map(|socket| socket.fd.as_raw_fd()).collect();
        Notifier::to_path(path).notify_with_fds("FDSTORE=1\nFDNAME=x", &fds);
        let (text, fds) = recv_with_fds(&sock);
        assert_eq!(text, "FDSTORE=1\nFDNAME=x");
        let received: Vec<_> = fds
            .into_iter()
            .map(|fd| Inherited::identify(fd).unwrap())
            .map(|socket| (socket.transport, socket.addr))
            .collect();
        let sent: Vec<_> = sent
            .iter()
            .map(|socket| (socket.transport, socket.addr))
            .collect();
        assert_eq!(received, sent, "the same sockets, in order");
        Notifier { target: None }.notify_with_fds("FDSTORE=1", &[]);
    }

    #[test]
    fn the_store_holds_the_listening_sockets_of_the_cores_and_no_other() {
        let (_dir, path, sock) = listen_notify();
        let notifier = Notifier::to_path(path);
        use crate::plan::ListenerKind::Http;
        // What the process before left in the store: three sockets for `a` (it had three
        // cores), two for `b`, and one for an address no listener has now.
        let (first_a, first_b, only) = (
            Inherited::fresh(Http),
            Inherited::fresh(Http),
            Inherited::fresh(Http),
        );
        let (a, b, gone) = (first_a.addr, first_b.addr, only.addr);
        let before = [
            first_a.sibling(Http),
            first_a.sibling(Http),
            first_a,
            first_b.sibling(Http),
            first_b,
            only,
        ];
        let cpu = crate::runtime::allowed_cpus()[0];
        let workers = crate::runtime::spawn_workers(
            &[cpu, cpu],
            crate::runtime::testing::generation(1, &[a, b]),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let name = |addr: std::net::SocketAddr| format!("tcp_127.0.0.1_{}", addr.port());
        let mut stored = Stored {
            enabled: true,
            names: Stored::count(&before),
        };
        let mut known = vec![(name(a), 3), (name(b), 2), (name(gone), 1)];
        known.sort();
        assert_eq!(stored.names, known);

        // A message with its sockets' addresses, in the order sent.
        let next = || {
            let (text, fds) = recv_with_fds(&sock);
            let addrs: Vec<_> = fds
                .into_iter()
                .map(|fd| Inherited::identify(fd).unwrap().addr)
                .collect();
            (text, addrs)
        };
        runtime.block_on(stored.sync(&workers, &notifier));
        let mut removed = vec![next(), next()];
        removed.sort();
        let mut expected = vec![
            (format!("FDSTOREREMOVE=1\nFDNAME={}", name(a)), vec![]),
            (format!("FDSTOREREMOVE=1\nFDNAME={}", name(gone)), vec![]),
        ];
        expected.sort();
        assert_eq!(
            removed, expected,
            "first out: the address no listener has, and the one with a socket more than cores"
        );
        let mut kept = vec![next(), next()];
        kept.sort();
        let mut expected = vec![
            (format!("FDSTORE=1\nFDNAME={}", name(a)), vec![a, a]),
            (format!("FDSTORE=1\nFDNAME={}", name(b)), vec![b, b]),
        ];
        expected.sort();
        assert_eq!(
            kept, expected,
            "then in: one message per address, a socket per core"
        );

        runtime.block_on(stored.sync(&workers, &notifier));
        let mut again = vec![next(), next()];
        again.sort();
        assert_eq!(again, expected, "nothing is removed when nothing changed");

        let mut disabled = Stored {
            enabled: false,
            names: Vec::new(),
        };
        runtime.block_on(disabled.sync(&workers, &notifier));
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(sock.recv(&mut buf).is_err(), "nothing without a store");
        crate::runtime::stop(workers, Instant::now());
    }

    #[cfg(feature = "kubernetes")]
    #[test]
    fn a_process_that_takes_over_waits_until_every_discovery_source_has_synced() {
        use crate::discover::{Found, SourceKey, SourceState};
        let plan = crate::runtime::testing::plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": [free_addr()], "https": [] },
                "sites": [{
                    "name": "shop",
                    "hosts": ["*"],
                    "routes": [{ "proxy": { "to": { "kubernetes": {
                        "namespace": "shop", "service": "web", "port": 8080,
                    } } } }],
                }],
            }),
        );
        let crate::plan::SourceSpec::Kubernetes(spec) = &plan.sources[0];
        let source = SourceKey::Kubernetes(spec.watch.clone());
        let endpoint: std::net::SocketAddr = "10.0.0.7:8080".parse().unwrap();
        let report = |state, endpoints: &[std::net::SocketAddr]| Found {
            source: source.clone(),
            endpoints: endpoints.into(),
            state,
        };
        let unreachable = SourceState::Unreachable {
            since: std::time::SystemTime::now(),
            error: "refused".into(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let start = |plan| {
            let mut live = Live::new(1);
            let (current, _) = assemble(plan, None, &mut live);
            (Arc::new(current), live)
        };

        let (mut current, mut live) = start(plan);
        let mut reports = std::collections::VecDeque::from([
            report(unreachable.clone(), &[]),
            report(SourceState::Synced, &[endpoint]),
        ]);
        let next = async || match reports.pop_front() {
            Some(found) => found,
            None => std::future::pending().await,
        };
        let waited = first_reports(
            next,
            &mut current,
            &[],
            &mut live.registry,
            Duration::from_secs(5),
        );
        runtime.block_on(waited).expect("the source synced");
        let origins: Vec<_> = current
            .upstreams
            .origins()
            .iter()
            .map(|origin| match origin.spec.addr {
                crate::plan::OriginAddr::Ip(addr) => Some(addr),
                crate::plan::OriginAddr::Name => None,
            })
            .collect();
        assert_eq!(
            origins,
            [Some(endpoint)],
            "and its endpoints are in the generation"
        );

        let plan = Arc::try_unwrap(current)
            .ok()
            .and_then(|generation| Arc::try_unwrap(generation.plan).ok())
            .expect("the only holder of the plan");
        let (mut current, mut live) = start(plan);
        let mut reports = std::collections::VecDeque::from([report(unreachable, &[])]);
        let next = async || match reports.pop_front() {
            Some(found) => found,
            None => std::future::pending().await,
        };
        let waited = first_reports(
            next,
            &mut current,
            &[],
            &mut live.registry,
            Duration::from_millis(100),
        );
        assert_eq!(
            runtime.block_on(waited),
            Err("kubernetes:shop/web:8080".to_owned()),
            "a source that only reports its API server unreachable has not synced"
        );
    }

    #[test]
    fn monotonic_usec_advances() {
        let a = monotonic_usec();
        std::thread::sleep(Duration::from_millis(5));
        let b = monotonic_usec();
        assert!(b >= a + 4_000, "{a} -> {b}");
    }

    #[test]
    fn worker_count_wraps_over_allowed_cpus() {
        let allowed = crate::runtime::allowed_cpus();
        assert_eq!(assign_cpus(None), allowed);
        assert_eq!(assign_cpus(Some(1)), vec![allowed[0]]);
        let many = assign_cpus(Some(allowed.len() as u16 * 2));
        assert_eq!(many.len(), allowed.len() * 2);
        assert_eq!(many[allowed.len()], allowed[0]);
    }

    /// The only test that raises process signals; the others in this binary never install
    /// handlers for them, so nothing else reacts.
    #[test]
    fn lifecycle_under_signals() {
        const RELOADS: u64 = 100;
        let _signals = disruptive_section();
        let (_dir, path, notifications) = listen_notify();
        let (a, b) = (free_addr(), free_addr());
        // Generations up to RELOADS listen on a and b; later ones on b alone. Generation
        // RELOADS + 2 fails to compile.
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let control = std::thread::spawn({
            let attempts = attempts.clone();
            move || {
                let mut load = |generation: u64| {
                    attempts.lock().unwrap().push(generation);
                    if generation == RELOADS + 2 {
                        return Err(vec![Diagnostic::error(None, "/sites/0", "broken")]);
                    }
                    let addrs: &[_] = if generation <= RELOADS { &[a, b] } else { &[b] };
                    Ok((plan(generation, addrs), Vec::new()))
                };
                serve(
                    &mut load,
                    Some(2),
                    &Notifier::to_path(path),
                    Start::default(),
                )
            }
        });
        assert_eq!(recv(&notifications), "READY=1\nSTATUS=serving generation 1");
        assert!(
            listening_here(a) && listening_here(b),
            "both listeners are bound"
        );

        let stop = Arc::new(AtomicBool::new(false));
        let hammered = Arc::new(AtomicUsize::new(0));
        let hammers: Vec<_> = (0..4)
            .map(|_| {
                let (stop, hammered) = (stop.clone(), hammered.clone());
                std::thread::spawn(move || {
                    let mut conn = connect(b);
                    let mut last = 0;
                    while !stop.load(Ordering::Relaxed) {
                        let generation = get(&mut conn).expect("keep-alive request during reloads");
                        assert!(generation >= last, "generations never go back");
                        last = generation;
                        hammered.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        let mut keep_alive = connect(a);
        assert_eq!(get(&mut keep_alive).unwrap(), 1);
        for generation in 2..=RELOADS {
            signal(libc::SIGHUP);
            let reloading = recv(&notifications);
            assert!(
                reloading.starts_with("RELOADING=1\nMONOTONIC_USEC="),
                "{reloading}"
            );
            let usec: u64 = reloading.rsplit('=').next().unwrap().parse().unwrap();
            assert!(usec <= monotonic_usec());
            assert_eq!(
                recv(&notifications),
                format!("READY=1\nSTATUS=serving generation {generation}")
            );
            assert_eq!(
                get(&mut keep_alive).unwrap(),
                generation,
                "the next request on the same connection runs under the new generation"
            );
        }

        signal(libc::SIGHUP);
        assert!(recv(&notifications).starts_with("RELOADING=1"));
        assert_eq!(
            recv(&notifications),
            format!("READY=1\nSTATUS=serving generation {}", RELOADS + 1)
        );
        assert!(
            !listening_here(a),
            "the listener the reload removed is closed"
        );
        std::io::Write::write_all(&mut keep_alive, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        let (head, _) = read_response(&mut keep_alive).unwrap();
        assert!(
            head.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "a connection accepted by the removed listener has no site under the new plan: {head}"
        );

        signal(libc::SIGHUP);
        assert!(recv(&notifications).starts_with("RELOADING=1"));
        assert_eq!(
            recv(&notifications),
            format!(
                "READY=1\nSTATUS=reload failed, still serving generation {}: /sites/0: broken",
                RELOADS + 1
            )
        );
        assert_eq!(get(&mut connect(b)).unwrap(), RELOADS + 1);

        stop.store(true, Ordering::Relaxed);
        for hammer in hammers {
            hammer.join().expect("a hammering client saw an error");
        }
        println!(
            "{} keep-alive requests on 4 connections across {} reloads, 0 errors",
            hammered.load(Ordering::Relaxed),
            RELOADS + 1
        );

        let mut idle = connect(b);
        assert_eq!(get(&mut idle).unwrap(), RELOADS + 1);
        signal(libc::SIGTERM);
        assert_eq!(recv(&notifications), "STOPPING=1");
        control.join().unwrap().unwrap();
        let mut rest = Vec::new();
        assert_eq!(
            std::io::Read::read_to_end(&mut idle, &mut rest).unwrap(),
            0,
            "drain closes idle connections"
        );
        assert!(
            !listening_here(b),
            "every listener is closed once serve returns"
        );
        assert_eq!(
            *attempts.lock().unwrap(),
            (1..=RELOADS + 2).collect::<Vec<_>>()
        );
    }
}
