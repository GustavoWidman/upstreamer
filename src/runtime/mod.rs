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

use crate::exchange::ExchangePool;
use crate::files::catalog::Catalog;
use crate::net::buf::BufPool;
use crate::plan::Plan;
use crate::proxy::pool::Pools;
use crate::tls::{CertStore, TicketKeys};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

/// What the control thread publishes: immutable, shared by all cores.
pub(crate) struct Generation {
    pub plan: Arc<Plan>,
    pub certs: Arc<CertStore>,
    pub tickets: Arc<TicketKeys>,
}

/// A core's view of one generation, built on the core when the generation arrives (so the
/// rustls configs and regex caches are this core's own).
pub(crate) struct CoreSnapshot {
    pub plan: Arc<Plan>,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub quic: Option<Arc<rustls::ServerConfig>>,
}

/// Search caches for the plan's regexes, one per regex, owned by the core.
pub(crate) struct RegexCaches {
    pub caches: Vec<regex_automata::meta::Cache>,
}

impl RegexCaches {
    /// One cache per regex of `plan`, indexed by `RegexId`.
    pub fn for_plan(plan: &Plan) -> RegexCaches {
        RegexCaches {
            caches: plan.regexes.iter().map(|r| r.create_cache()).collect(),
        }
    }
}

/// Coarse clock: unix seconds and the formatted `Date` value, refreshed once per second by a
/// core-local timer (no `clock_gettime` or formatting per response).
pub(crate) struct Clock {
    pub unix: Cell<i64>,
    pub http_date: RefCell<[u8; 29]>,
}

impl Clock {
    /// Reads the system clock now; the core's timer calls [`Clock::tick`] every second.
    pub fn new() -> Clock {
        let clock = Clock {
            unix: Cell::new(0),
            http_date: RefCell::new(*b"Thu, 01 Jan 1970 00:00:00 GMT"),
        };
        clock.tick();
        clock
    }
    /// Refreshes `unix` and `http_date` (IMF-fixdate) from the system clock.
    pub fn tick(&self) {
        todo!()
    }
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
    pub draining: Cell<bool>,
}

impl Core {
    /// The current snapshot. Held by a request for its duration; never across requests.
    pub fn snapshot(&self) -> Rc<CoreSnapshot> {
        self.snapshot.borrow().clone()
    }
    /// Installs a new generation: builds this core's TLS configs and regex caches, re-indexes
    /// upstream pools, drops mutable catalog entries, binds listeners whose key is new and
    /// closes those whose key is gone (their connections finish their current request).
    pub fn install(&self, generation: &Generation) {
        todo!()
    }
}

/// Messages from the control thread to a core.
pub(crate) enum ToCore {
    Install(Arc<Generation>),
    /// Stop accepting, GOAWAY/close idle, finish in-flight within `deadline`.
    Drain {
        deadline: std::time::Instant,
    },
}

/// Handle the control thread keeps per core.
pub(crate) struct Worker {
    pub thread: std::thread::JoinHandle<()>,
    pub tx: tokio::sync::mpsc::UnboundedSender<ToCore>,
    pub cpu: usize,
}

/// Spawns one pinned worker per CPU. Each binds its listeners for the initial generation
/// before reporting ready; a bind failure on any core is a start failure.
pub(crate) fn spawn_workers(
    cpus: &[usize],
    initial: Arc<Generation>,
) -> Result<Vec<Worker>, crate::StartError> {
    todo!()
}

/// A worker thread's body: pin, build the runtime, install, then run accept loops (one local
/// task per listener), the snapshot mailbox, the 1s clock and the pool sweeper.
fn worker_main(
    index: usize,
    cpu: usize,
    rx: tokio::sync::mpsc::UnboundedReceiver<ToCore>,
    initial: Arc<Generation>,
    ready: std::sync::mpsc::Sender<Result<(), crate::StartError>>,
) {
    todo!()
}

/// Accept loop of one TCP listener: per connection, spawn_local(TLS accept -> h1|h2 driver) or
/// the h1 driver directly on cleartext listeners.
async fn accept_loop(core: Rc<Core>, listener: crate::net::listen::Listener) {
    todo!()
}
