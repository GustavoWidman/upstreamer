//! Per-core idle upstream connections: one LIFO stack per origin (the most recently used
//! connection is the warmest and least likely to have been closed by the origin). Accessed only
//! by tasks of its core, synchronously, so a `RefCell` borrow never spans an await.

use super::UpstreamConn;
use crate::plan::{Plan, UpstreamId};
use std::cell::RefCell;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct Pools {
    idle: RefCell<Vec<Vec<UpstreamConn>>>,
}

impl Pools {
    /// Pops the newest idle connection of `id` that is still fresh (idle < origin's `idle`)
    /// and shows no EOF/readable event (checked from the reactor's readiness bits, no
    /// syscall). Stale ones are dropped on the way.
    pub fn checkout(&self, id: UpstreamId, now: Instant) -> Option<UpstreamConn> {
        todo!()
    }
    /// Returns a connection whose last response was fully read and allowed reuse. Over the
    /// origin's `max_idle_per_core`, the oldest is closed.
    pub fn checkin(&self, conn: UpstreamConn, now: Instant) {
        todo!()
    }
    /// Closes connections idle past their origin's limit. Run by a core-local timer every 5s.
    pub fn sweep(&self, plan: &Plan, now: Instant) {
        todo!()
    }
    /// On a new plan: re-index by the new origin ids, closing connections to origins that no
    /// longer exist or changed address or TLS settings.
    pub fn adopt(&self, old: &Plan, new: &Plan) {
        todo!()
    }
}
