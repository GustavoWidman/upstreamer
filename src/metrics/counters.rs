//! The per-snapshot counters and their layout.

use crate::msg::Status;
use crate::plan::{ListenerKey, OriginId, Plan, RouteSlot};
use crate::upstream::Upstreams;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

/// Where each series' cells start, for one (plan, upstreams) pair. Built once per generation
/// or epoch by the control thread, shared by every core's snapshot.
#[derive(Default)]
pub(crate) struct Layout {}

impl Layout {
    pub fn build(plan: &Plan, upstreams: &Upstreams) -> Arc<Layout> {
        let _ = (plan, upstreams);
        Arc::default()
    }
}

/// One snapshot's counters on one core. Only that core's thread touches them.
pub(crate) struct Counters {
    layout: Arc<Layout>,
    /// Where this snapshot's counts go when it drops.
    retired: Rc<RefCell<Retired>>,
}

impl Counters {
    pub fn new(layout: Arc<Layout>, retired: Rc<RefCell<Retired>>) -> Counters {
        Counters { layout, retired }
    }

    /// A finished request: its status class, its duration bucket and sum.
    #[inline]
    pub fn request(&self, route: RouteSlot, status: Status, took: Duration) {
        let _ = (route, status, took);
    }

    /// The first attempt's start to the origin's response head, or the failure's cause.
    #[inline]
    pub fn upstream(&self, origin: OriginId, answer: Result<Status, Cause>, took: Duration) {
        let _ = (origin, answer, took);
    }

    /// A `limit` step answered 429.
    #[inline]
    pub fn limited(&self, route: RouteSlot) {
        let _ = route;
    }

    /// A retry moved off this origin.
    #[inline]
    pub fn retried(&self, origin: OriginId) {
        let _ = origin;
    }
}

/// Why the last attempt of a proxied request failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    Connect,
    Timeout,
    Tls,
    Reset,
    Status,
}

/// Totals of the core's dropped snapshots, by label.
#[derive(Default)]
pub(crate) struct Retired {}

/// Per-connection counters on the `Core`: accepted, open, handshakes by result, by listener.
#[derive(Default)]
pub(crate) struct ConnCounters {
    by_listener: RefCell<Vec<(ListenerKey, [Cell<u64>; 5])>>,
}

impl ConnCounters {
    /// A connection (TCP) or an incoming QUIC connection was accepted on `listener`.
    #[inline]
    pub fn accepted(&self, listener: ListenerKey) {
        let _ = listener;
    }

    /// A TLS handshake on `listener` ended, completed or not.
    #[inline]
    pub fn handshake(&self, listener: ListenerKey, ok: bool) {
        let _ = (listener, ok);
    }
}

/// What a core's tick hands the hub.
#[derive(Default)]
pub(crate) struct Published {
    pub series: Vec<(Arc<str>, Vec<u64>)>,
    pub conns: Vec<(ListenerKey, [u64; 5])>,
    /// Per origin label: requests in flight on this core, summed by the scrape.
    pub in_flight: Vec<(Arc<str>, u32)>,
}
