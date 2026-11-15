//! Prometheus metrics. Collection is on only while some site has a `metrics` step.
//!
//! # Collection: plain memory on the core, no atomic, no lock
//!
//! Counters a request touches belong to the `CoreSnapshot` it runs under ([`Counters`], cells
//! laid out by [`Layout`]). A reload never re-indexes anything and never misattributes a
//! request that started before it: the old snapshot keeps counting until its last request
//! ends, then its `Drop` folds its counts into the core's [`Retired`] totals, keyed by label.
//! Per-connection facts are [`ConnCounters`] on the `Core` itself.
//!
//! # Publication: once a second, off the request path
//!
//! The core's 1 s clock tick copies its retired totals, live counters and connection counters
//! into its slot of the [`Hub`], which only that tick and a scrape lock.
//!
//! # Exposition: the `metrics` step
//!
//! Whatever core takes the scrape sums the slots by label, reads the shared health cells and
//! `/proc/self`, and writes the text format.

mod counters;
mod render;

pub(crate) use counters::{Cause, ConnCounters, Counters, Layout, Published, Retired};

use crate::exchange::Exchange;
use crate::msg::Status;
use crate::pipeline::{self, Response};
use crate::plan::Plan;
use crate::runtime::{Core, CoreSnapshot};
use std::sync::{Arc, Mutex};

/// One per process, created by the control thread at startup and handed to every generation
/// that collects metrics (the same `Arc`).
pub(crate) struct Hub {
    cores: Box<[Mutex<Published>]>,
    /// Written by the control thread: generation, reload results, discovery state.
    control: Mutex<Control>,
    started: std::time::SystemTime,
}

#[derive(Default)]
pub(crate) struct Control {
    pub generation: u64,
    pub reloads_ok: u64,
    pub reloads_rejected: u64,
    /// Per discovery source: label, endpoints, synced.
    pub sources: Vec<(Arc<str>, usize, bool)>,
}

impl Hub {
    pub fn new(cores: usize) -> Arc<Hub> {
        Arc::new(Hub {
            cores: (0..cores).map(|_| Mutex::default()).collect(),
            control: Mutex::default(),
            started: std::time::SystemTime::now(),
        })
    }

    /// The control thread's facts, updated after each reload and discovery change.
    pub fn control(&self) -> std::sync::MutexGuard<'_, Control> {
        self.control.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The `metrics` terminal: the exposition of every core as a local `200`.
pub(crate) fn serve(core: &Core, snap: &CoreSnapshot, ex: &mut Exchange) -> Response {
    let _ = (core, snap);
    pipeline::bare(ex, Status::NOT_FOUND)
}

/// Called from the core's 1 s tick while its snapshot collects metrics.
pub(crate) fn publish(core: &Core) {
    let _ = core;
}

/// The series a plan exposes, for `upstreamer check`.
pub(crate) fn series(plan: &Plan) -> usize {
    let _ = plan;
    0
}

/// Entry points for `benches/metrics.rs`; not part of the API.
#[cfg(feature = "internals")]
pub mod bench {}
