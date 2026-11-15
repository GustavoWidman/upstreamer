//! Origin health: the shared cell, passive outcomes, and active probes.
//!
//! Time is the health clock: whole seconds since process start (`runtime::Clock::mono`), so
//! every core compares the same numbers and a wall-clock jump cannot extend an ejection.

use crate::plan::PassivePlan;
use crate::proxy::pool::OriginLocal;
use crate::upstream::Origin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

/// One origin's health, shared by every core and carried across epochs by origin identity.
/// 64-byte aligned: a write (a health transition, rare) invalidates no other origin's line.
#[repr(align(64))]
#[derive(Debug, Default)]
pub(crate) struct Health {
    /// Health-clock second until which passive checks keep the origin out. Written with
    /// `fetch_max` by any core.
    ejected_until: AtomicU32,
    /// Consecutive ejections, for the doubling cooldown.
    ejections: AtomicU8,
    /// The last probe verdict. Written only by the origin's probing core.
    probe_down: AtomicBool,
}

impl Health {
    /// Two relaxed loads; no write.
    #[inline]
    pub fn eligible(&self, now: u32) -> bool {
        !self.probe_down.load(Ordering::Relaxed)
            && self.ejected_until.load(Ordering::Relaxed) <= now
    }

    pub fn probe_down(&self) -> bool {
        self.probe_down.load(Ordering::Relaxed)
    }

    /// A probe verdict. Called only by the origin's probing core.
    pub(crate) fn set_probe(&self, down: bool) {
        self.probe_down.store(down, Ordering::Relaxed)
    }
}

/// How one attempt ended, as far as health is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A response head with a status not in `fail_statuses`.
    Answered,
    /// Connect refused or timed out, TLS failed, reset or EOF before the head,
    /// response-header timeout, or a status in `fail_statuses`.
    Failed,
    /// The client went away, or the attempt was not the origin's fault: not counted.
    Neutral,
}

/// Records an attempt's outcome on this core.
pub(crate) fn observe(
    origin: &Origin,
    local: &OriginLocal,
    passive: Option<&PassivePlan>,
    outcome: Outcome,
    now: u32,
) {
    let _ = (origin, local, passive, outcome, now);
}

/// The probe loop of one core, spawned next to the pool sweeper. Returns at once while no
/// origin has a probe.
pub(crate) async fn probe_loop(core: std::rc::Rc<crate::runtime::Core>) {
    let _ = core;
}
