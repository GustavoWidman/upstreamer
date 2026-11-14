//! Per-core state for reaching origins: idle connections, resolved names and TLS client
//! configs. Accessed only by tasks of its core, synchronously, so a `RefCell` borrow never
//! spans an await.
//!
//! Idle connections sit in one LIFO stack per origin: the most recently used connection is the
//! warmest and the least likely to have been closed by the origin.

use super::conn::UpstreamConn;
use crate::plan::{Plan, UpstreamId, UpstreamPlan};
use smallvec::SmallVec;
use std::cell::{Cell, OnceCell, RefCell};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a resolved origin name is used before it is resolved again.
const NAME_TTL: Duration = Duration::from_secs(30);

pub(crate) struct Pools {
    /// Indexed by [`UpstreamId`] of the plan the core serves.
    idle: RefCell<Vec<Vec<UpstreamConn>>>,
    /// Indexed like `idle`.
    names: RefCell<Vec<Option<Resolved>>>,
    /// Client configs with and without certificate verification, built on first use.
    tls: [OnceCell<Arc<rustls::ClientConfig>>; 2],
    /// The time of the last sweep. Idle ages are measured against it, so checking a
    /// connection in reads no clock; an age is at most one sweep interval short.
    now: Cell<Instant>,
}

struct Resolved {
    addrs: SmallVec<[SocketAddr; 4]>,
    at: Instant,
}

impl Default for Pools {
    fn default() -> Self {
        Pools {
            idle: RefCell::default(),
            names: RefCell::default(),
            tls: Default::default(),
            now: Cell::new(Instant::now()),
        }
    }
}

impl Pools {
    /// Pops the newest idle connection to `id` on which the origin neither closed nor sent
    /// bytes meanwhile (read from the reactor's readiness, no syscall). Dead ones are closed
    /// on the way.
    pub fn checkout(&self, id: UpstreamId) -> Option<UpstreamConn> {
        let mut idle = self.idle.borrow_mut();
        let stack = idle.get_mut(id.0 as usize)?;
        while let Some(conn) = stack.pop() {
            if !conn.io.hung_up_or_readable() {
                return Some(conn);
            }
        }
        None
    }

    /// Keeps a connection whose last response was fully read and allowed reuse. Over the
    /// origin's `max_idle_per_core`, the oldest is closed.
    pub fn checkin(&self, mut conn: UpstreamConn, up: &UpstreamPlan) {
        conn.idle_since = self.now.get();
        let mut idle = self.idle.borrow_mut();
        let index = up.id.0 as usize;
        if idle.len() <= index {
            idle.resize_with(index + 1, Vec::new);
        }
        let stack = &mut idle[index];
        if stack.len() >= usize::from(up.max_idle_per_core) {
            stack.remove(0);
        }
        stack.push(conn);
    }

    /// Closes connections idle past their origin's limit, and those the origin closed. Run by
    /// a core-local timer every few seconds.
    pub fn sweep(&self, plan: &Plan, now: Instant) {
        self.now.set(now);
        let mut idle = self.idle.borrow_mut();
        idle.truncate(plan.upstreams.len());
        for (stack, up) in idle.iter_mut().zip(plan.upstreams.iter()) {
            stack.retain(|conn| {
                now.duration_since(conn.idle_since) < up.idle && !conn.io.hung_up_or_readable()
            });
        }
    }

    /// On a new plan: re-indexes by the new origin ids, closing connections to origins that
    /// are gone or whose address or TLS settings changed. Resolved names are forgotten.
    pub fn adopt(&self, old: &Plan, new: &Plan) {
        let stacks = self.idle.take();
        let mut adopted: Vec<Vec<UpstreamConn>> = Vec::new();
        adopted.resize_with(new.upstreams.len(), Vec::new);
        for (stack, was) in stacks.into_iter().zip(old.upstreams.iter()) {
            let Some(now) = new.upstreams.iter().find(|u| same_origin(was, u)) else {
                continue;
            };
            adopted[now.id.0 as usize].extend(stack.into_iter().map(|mut conn| {
                conn.upstream = now.id;
                conn.generation = new.generation;
                conn
            }));
        }
        *self.idle.borrow_mut() = adopted;
        self.names.borrow_mut().clear();
    }

    /// The addresses `up`'s name resolved to, while they are fresh.
    pub fn resolved(&self, up: &UpstreamPlan) -> Option<SmallVec<[SocketAddr; 4]>> {
        let names = self.names.borrow();
        let entry = names.get(up.id.0 as usize)?.as_ref()?;
        (entry.at.elapsed() < NAME_TTL).then(|| entry.addrs.clone())
    }

    /// Remembers what `up`'s name resolved to, the address that answered first.
    pub fn remember(&self, up: &UpstreamPlan, addrs: SmallVec<[SocketAddr; 4]>) {
        let mut names = self.names.borrow_mut();
        let index = up.id.0 as usize;
        if names.len() <= index {
            names.resize_with(index + 1, || None);
        }
        names[index] = Some(Resolved {
            addrs,
            at: Instant::now(),
        });
    }

    /// Forgets `up`'s addresses, after none of them took a connection.
    pub fn forget(&self, up: &UpstreamPlan) {
        if let Some(entry) = self.names.borrow_mut().get_mut(up.id.0 as usize) {
            *entry = None;
        }
    }

    /// This core's TLS client config. Sessions are cached in it, so a redial resumes.
    pub fn client_tls(&self, verify: bool) -> Arc<rustls::ClientConfig> {
        self.tls[usize::from(verify)]
            .get_or_init(|| {
                let mut config = (*crate::tls::client_config(verify)).clone();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                Arc::new(config)
            })
            .clone()
    }

    #[cfg(test)]
    pub fn idle_count(&self, id: UpstreamId) -> usize {
        self.idle.borrow().get(id.0 as usize).map_or(0, Vec::len)
    }
}

fn same_origin(a: &UpstreamPlan, b: &UpstreamPlan) -> bool {
    let tls = |u: &UpstreamPlan| u.tls.as_ref().map(|t| (t.server_name.clone(), t.verify));
    a.host == b.host && a.port == b.port && tls(a) == tls(b)
}
