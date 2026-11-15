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

use super::{BindFailure, Generation, TlsState, ToCore, Worker};
use crate::access::{self, OpenFailure};
use crate::log::{error, info, warning};
use crate::plan::{Diagnostic, ListenerKind, Plan};
use crate::tls::{self, CertProblem, TicketKeys};
use crate::{RunOptions, StartError};
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
    serve(
        &mut |generation| crate::plan::load(&path, generation),
        opts.workers,
        &Notifier::from_env(),
    )
}

/// Starts the cores, then serves signals until SIGTERM or SIGINT. Blocks the calling thread.
pub(crate) fn serve(
    load: &mut LoadPlan<'_>,
    workers: Option<u16>,
    notifier: &Notifier,
) -> Result<(), StartError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(StartError::Runtime)?;
    runtime.block_on(async {
        // Handlers first: from READY=1 on, a SIGHUP must reload rather than kill.
        let mut hangup = signal(SignalKind::hangup()).map_err(StartError::Runtime)?;
        let mut terminate = signal(SignalKind::terminate()).map_err(StartError::Runtime)?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(StartError::Runtime)?;

        let mut generation = 1;
        let (current, warnings, problems) =
            rebuild(load, None, generation).map_err(StartError::Config)?;
        report(&warnings, &problems);
        let mut current = Arc::new(current);
        let cpus = assign_cpus(workers.or(current.plan.workers));
        let workers = super::spawn_workers(&cpus, current.clone())?;
        info!(
            "serving generation {generation} on {} cores, {} listeners",
            workers.len(),
            current.plan.listeners.len()
        );
        notifier.notify(&format!("READY=1\nSTATUS=serving generation {generation}"));

        let mut rotate = tokio::time::interval_at(
            tokio::time::Instant::now() + TICKET_ROTATION,
            TICKET_ROTATION,
        );
        loop {
            tokio::select! {
                _ = hangup.recv() => {
                    generation += 1;
                    reload(load, &mut current, generation, &workers, notifier).await;
                }
                _ = rotate.tick() => {
                    if let Some(tls) = &current.tls {
                        let next = Arc::new(Generation {
                            plan: current.plan.clone(),
                            tls: Some(TlsState {
                                certs: tls.certs.clone(),
                                tickets: Arc::new(tls.tickets.rotated()),
                            }),
                            access: current.access.clone(),
                        });
                        log_bind_failures(&publish(&workers, next.clone()).await);
                        current = next;
                    }
                }
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
            }
        }
        shutdown(workers, current.plan.server.shutdown, notifier);
        Ok(())
    })
}

async fn reload(
    load: &mut LoadPlan<'_>,
    current: &mut Arc<Generation>,
    generation: u64,
    workers: &[Worker],
    notifier: &Notifier,
) {
    notifier.notify(&format!("RELOADING=1\nMONOTONIC_USEC={}", monotonic_usec()));
    let status = match rebuild(load, Some(current), generation) {
        Ok((next, warnings, problems)) => {
            report(&warnings, &problems);
            let next = Arc::new(next);
            let failures = publish(workers, next.clone()).await;
            log_bind_failures(&failures);
            if next.plan.workers != current.plan.workers {
                warning!("a changed worker count applies at the next restart");
            }
            *current = next;
            info!("serving generation {generation}");
            let mut status = format!("serving generation {generation}");
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
#[derive(Default)]
pub(crate) struct Problems {
    pub certs: Vec<CertProblem>,
    pub logs: Vec<OpenFailure>,
}

/// Builds the next generation from disk, opening every access log file anew. `Err` keeps the
/// current one.
pub(crate) fn rebuild(
    load: &mut LoadPlan<'_>,
    current: Option<&Generation>,
    generation: u64,
) -> Result<(Generation, Vec<Diagnostic>, Problems), Vec<Diagnostic>> {
    let (plan, warnings) = load(generation)?;
    let previous = current.and_then(|g| g.tls.as_ref());
    let (tls, problems) = if plan
        .listeners
        .iter()
        .any(|l| l.key.kind != ListenerKind::Http)
    {
        let (certs, problems) = tls::load(&plan.certs, previous.map(|t| &*t.certs));
        let tickets = previous.map_or_else(
            || Arc::new(TicketKeys::generate(TICKET_LIFETIME_SECS)),
            |t| t.tickets.clone(),
        );
        let certs = Arc::new(certs);
        (Some(TlsState { certs, tickets }), problems)
    } else {
        (None, Vec::new())
    };
    let (files, logs) = access::Files::open(&plan.access_logs);
    let plan = Arc::new(plan);
    let next = Generation {
        plan,
        tls,
        access: Arc::new(files),
    };
    Ok((
        next,
        warnings,
        Problems {
            certs: problems,
            logs,
        },
    ))
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
    use crate::runtime::testing::{connect, free_addr, get, plan, read_response};
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

    fn recv(sock: &UnixDatagram) -> String {
        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf).expect("a notification");
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
                serve(&mut load, Some(2), &Notifier::to_path(path))
            }
        });
        assert_eq!(recv(&notifications), "READY=1\nSTATUS=serving generation 1");

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
            std::net::TcpStream::connect(a).is_err(),
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
        assert!(std::net::TcpStream::connect(b).is_err());
        assert_eq!(
            *attempts.lock().unwrap(),
            (1..=RELOADS + 2).collect::<Vec<_>>()
        );
    }
}
