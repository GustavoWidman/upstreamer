//! The per-snapshot counters, their layout, and each core's totals.
//!
//! A snapshot's counters are one flat slice of `Cell<u64>`. Route series come first, one
//! block of [`route::LEN`] cells per `RouteSlot` (so a request finds its block by
//! multiplying, with no lookup), then one block of [`upstream::LEN`] cells per distinct
//! origin label. A series is identified across snapshots, reloads and epochs by its [`Key`],
//! the rendered text of its labels, so counts continue under the same labels whatever index
//! they had in a plan.

use super::Hub;
use crate::msg::Status;
use crate::plan::{Action, Block, ListenerKey, OriginId, Plan, RouteSlot};
use crate::upstream::Upstreams;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::Duration;

/// Upper bounds of the latency buckets, in microseconds; `+Inf` is implicit. One list for
/// every histogram.
pub(crate) const BUCKETS_US: [u64; 13] = [
    1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000,
    5_000_000, 10_000_000,
];

/// [`BUCKETS_US`] in seconds, as the `le` label prints them.
pub(crate) const BUCKET_LABELS: [&str; 13] = [
    "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5",
    "10",
];

/// Buckets of a histogram, `+Inf` included. Cells hold per-bucket counts; the exposition
/// makes them cumulative.
pub(crate) const BUCKETS: usize = BUCKETS_US.len() + 1;

/// Status classes `1xx` to `5xx`.
pub(crate) const CLASSES: usize = 5;

/// Cells of one route series.
pub(crate) mod route {
    use super::{BUCKETS, CLASSES};
    /// Requests by status class.
    pub const REQUESTS: usize = 0;
    /// The duration histogram's buckets, then its sum in microseconds.
    pub const DURATION: usize = REQUESTS + CLASSES;
    pub const DURATION_SUM: usize = DURATION + BUCKETS;
    /// Requests a `limit` step answered with 429.
    pub const REJECTED: usize = DURATION_SUM + 1;
    pub const LEN: usize = REJECTED + 1;
}

/// Cells of one upstream series.
pub(crate) mod upstream {
    use super::{BUCKETS, CLASSES};
    /// Response heads by status class.
    pub const RESPONSES: usize = 0;
    /// Failed attempts by [`Cause`](super::Cause).
    pub const FAILURES: usize = RESPONSES + CLASSES;
    /// The response-head histogram's buckets, then its sum in microseconds.
    pub const RESPONSE: usize = FAILURES + super::Cause::ALL.len();
    pub const RESPONSE_SUM: usize = RESPONSE + BUCKETS;
    /// Attempts moved off this origin to another.
    pub const RETRIES: usize = RESPONSE_SUM + 1;
    pub const LEN: usize = RETRIES + 1;
}

/// A series' identity: the label text it renders with, already escaped
/// (`site="shop",route="web"` or `origin="10.0.1.21:8080"`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Key {
    Route(Arc<str>),
    Upstream(Arc<str>),
}

impl Key {
    /// The number of cells the series has.
    pub fn len(&self) -> usize {
        match self {
            Key::Route(_) => route::LEN,
            Key::Upstream(_) => upstream::LEN,
        }
    }

    pub fn labels(&self) -> &str {
        match self {
            Key::Route(l) | Key::Upstream(l) => l,
        }
    }
}

/// `site="..",route=".."` for a route label.
pub(crate) fn route_labels(site: &str, route: &str) -> Arc<str> {
    let mut out = String::with_capacity(site.len() + route.len() + 16);
    out.push_str("site=\"");
    escape_into(site, &mut out);
    out.push_str("\",route=\"");
    escape_into(route, &mut out);
    out.push('"');
    out.into()
}

/// `origin=".."` for an origin or discovery source label.
pub(crate) fn origin_labels(origin: &str) -> Arc<str> {
    let mut out = String::with_capacity(origin.len() + 10);
    out.push_str("origin=\"");
    escape_into(origin, &mut out);
    out.push('"');
    out.into()
}

/// A label value as the text format writes it: backslash, double quote and line feed escaped.
pub(crate) fn escape_into(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

/// Where each series' cells start, for one (plan, upstreams) pair. Built once per generation
/// or epoch by the control thread, shared by every core's snapshot.
pub(crate) struct Layout {
    /// Route series: `plan.routes.len()` blocks from cell 0.
    routes: usize,
    /// By `OriginId`: the first cell of the origin's upstream series. Origins with one label
    /// (the origins of a discovery source) share their series.
    origins: Box<[u32]>,
    /// Every series with its first cell, routes first.
    pub(super) series: Box<[(Key, u32)]>,
    /// By `LimitId`: the route labels of the `limit` step that owns the table.
    pub(super) limits: Box<[Arc<str>]>,
    len: usize,
}

impl Layout {
    pub fn build(plan: &Plan, upstreams: &Upstreams) -> Arc<Layout> {
        let mut series: Vec<(Key, u32)> = plan
            .routes
            .iter()
            .enumerate()
            .map(|(i, l)| {
                (
                    Key::Route(route_labels(&l.site, &l.route)),
                    (i * route::LEN) as u32,
                )
            })
            .collect();
        let mut next = plan.routes.len() * route::LEN;
        let mut by_label: HashMap<&str, u32> = HashMap::new();
        let origins = upstreams
            .origins()
            .iter()
            .map(|origin| {
                *by_label.entry(&origin.label).or_insert_with(|| {
                    let at = next as u32;
                    series.push((Key::Upstream(origin_labels(&origin.label)), at));
                    next += upstream::LEN;
                    at
                })
            })
            .collect();
        let mut limits: Vec<Option<Arc<str>>> = vec![None; plan.limits.len()];
        for site in plan.sites.iter() {
            limit_routes(&site.routes, plan, &mut limits);
        }
        let limits = limits
            .into_iter()
            .zip(plan.limits.iter())
            .map(|(found, spec)| found.unwrap_or_else(|| route_labels(&spec.site, &spec.step)))
            .collect();
        Arc::new(Layout {
            routes: plan.routes.len(),
            origins,
            series: series.into(),
            limits,
            len: next,
        })
    }

    /// The first cell of `slot`'s route series, if the plan has that slot.
    #[inline]
    fn route(&self, slot: RouteSlot) -> Option<usize> {
        let slot = usize::from(slot.0);
        (slot < self.routes).then_some(slot * route::LEN)
    }

    #[inline]
    fn origin(&self, origin: OriginId) -> Option<usize> {
        self.origins
            .get(usize::from(origin.0))
            .map(|&at| at as usize)
    }

    pub(super) fn has(&self, key: &Key) -> bool {
        self.series.iter().any(|(k, _)| k == key)
    }
}

/// Records, by `LimitId`, the route labels of each `limit` step in `block`.
fn limit_routes(block: &Block, plan: &Plan, out: &mut [Option<Arc<str>>]) {
    for step in block.steps.iter() {
        match &step.action {
            Action::Limit(limit) => {
                if let (Some(slot), Some(label)) = (
                    out.get_mut(usize::from(limit.table.0)),
                    plan.routes.get(usize::from(limit.route.0)),
                ) {
                    *slot = Some(route_labels(&label.site, &label.route));
                }
            }
            Action::Block(inner) => limit_routes(inner, plan, out),
            _ => {}
        }
    }
}

/// One snapshot's counters on one core. Only that core's thread touches them.
pub(crate) struct Counters {
    cells: Rc<[Cell<u64>]>,
    pub(super) layout: Arc<Layout>,
    /// The process's hub, where this core publishes these counts.
    pub(super) hub: Arc<Hub>,
    /// Where this snapshot's counts go when it drops.
    retired: Rc<RefCell<Retired>>,
}

#[inline]
fn add(cell: &Cell<u64>, n: u64) {
    cell.set(cell.get().wrapping_add(n));
}

/// The bucket of a duration in microseconds: the first whose bound holds it.
#[inline]
fn bucket(us: u64) -> usize {
    BUCKETS_US.iter().map(|&b| usize::from(us > b)).sum()
}

#[inline]
fn class(status: Status) -> usize {
    usize::from(status.code() / 100).clamp(1, CLASSES) - 1
}

#[inline]
fn micros(took: Duration) -> u64 {
    // Not `as_micros`: its u128 division costs more than every add of a request together.
    took.as_secs()
        .saturating_mul(1_000_000)
        .saturating_add(u64::from(took.subsec_micros()))
}

impl Counters {
    pub fn new(layout: Arc<Layout>, hub: Arc<Hub>, retired: Rc<RefCell<Retired>>) -> Counters {
        let cells: Rc<[Cell<u64>]> = (0..layout.len).map(|_| Cell::new(0)).collect();
        retired
            .borrow_mut()
            .live
            .push((Rc::downgrade(&cells), layout.clone()));
        Counters {
            cells,
            layout,
            hub,
            retired,
        }
    }

    #[inline]
    fn block<const N: usize>(&self, at: usize) -> Option<&[Cell<u64>; N]> {
        self.cells.get(at..at + N)?.try_into().ok()
    }

    /// A finished request: its status class, its duration bucket and sum. Three `Cell` adds.
    #[inline]
    pub fn request(&self, route: RouteSlot, status: Status, took: Duration) {
        let Some(at) = self.layout.route(route) else {
            return;
        };
        let Some(cells) = self.block::<{ route::LEN }>(at) else {
            return;
        };
        let us = micros(took);
        add(&cells[route::REQUESTS + class(status)], 1);
        add(&cells[route::DURATION + bucket(us)], 1);
        add(&cells[route::DURATION_SUM], us);
    }

    /// The first attempt's start to the origin's response head, or the failure's cause.
    #[inline]
    pub fn upstream(&self, origin: OriginId, answer: Result<Status, Cause>, took: Duration) {
        let Some(at) = self.layout.origin(origin) else {
            return;
        };
        let Some(cells) = self.block::<{ upstream::LEN }>(at) else {
            return;
        };
        match answer {
            Ok(status) => {
                let us = micros(took);
                add(&cells[upstream::RESPONSES + class(status)], 1);
                add(&cells[upstream::RESPONSE + bucket(us)], 1);
                add(&cells[upstream::RESPONSE_SUM], us);
            }
            Err(cause) => add(&cells[upstream::FAILURES + cause.index()], 1),
        }
    }

    /// A `limit` step answered 429.
    #[inline]
    pub fn limited(&self, route: RouteSlot) {
        if let Some(cell) = self
            .layout
            .route(route)
            .and_then(|at| self.cells.get(at + route::REJECTED))
        {
            add(cell, 1);
        }
    }

    /// A retry moved off this origin.
    #[inline]
    pub fn retried(&self, origin: OriginId) {
        if let Some(cell) = self
            .layout
            .origin(origin)
            .and_then(|at| self.cells.get(at + upstream::RETRIES))
        {
            add(cell, 1);
        }
    }
}

impl Drop for Counters {
    /// Folds the counts into the core's totals by label: no request of this snapshot can
    /// still count, since each holds the snapshot while it runs.
    fn drop(&mut self) {
        let mut retired = self.retired.borrow_mut();
        for (key, at) in self.layout.series.iter() {
            let at = *at as usize;
            retired.fold(key, &self.cells[at..at + key.len()]);
        }
        let this = Rc::as_ptr(&self.cells);
        retired
            .live
            .retain(|(cells, _)| !std::ptr::addr_eq(cells.as_ptr(), this));
    }
}

/// Why the last attempt of a proxied request failed. Discriminants start at 1, so an
/// `observe::Answer` of 0 means no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum Cause {
    Connect = 1,
    Timeout,
    Tls,
    Reset,
    Status,
}

impl Cause {
    pub const ALL: [Cause; 5] = [
        Cause::Connect,
        Cause::Timeout,
        Cause::Tls,
        Cause::Reset,
        Cause::Status,
    ];

    pub fn index(self) -> usize {
        self as usize - 1
    }

    pub fn from_code(code: u16) -> Option<Cause> {
        Cause::ALL.get(usize::from(code).checked_sub(1)?).copied()
    }

    pub fn label(self) -> &'static str {
        match self {
            Cause::Connect => "connect",
            Cause::Timeout => "timeout",
            Cause::Tls => "tls",
            Cause::Reset => "reset",
            Cause::Status => "status",
        }
    }
}

/// How long a label absent from the current plan keeps its retired totals.
pub(crate) const RETIRE_AFTER: u32 = 600;

/// Totals of one series' dropped snapshots on one core.
struct Totals {
    values: Box<[u64]>,
    /// The core's health clock (whole seconds) when the series was first seen missing from
    /// the current layout.
    absent_since: Option<u32>,
}

/// A live snapshot's cells, and where its series are in them.
type Live = (Weak<[Cell<u64>]>, Arc<Layout>);

/// A core's totals of its dropped snapshots, by label, its live snapshots, and the scratch
/// its tick sums them into. Core-local: `Rc` and `RefCell`, touched off the request path.
#[derive(Default)]
pub(crate) struct Retired {
    totals: HashMap<Key, Totals>,
    /// The counters of every snapshot alive on the core (the current one, and older ones
    /// still held by requests or tunnels).
    live: Vec<Live>,
    sums: Sums,
}

impl Retired {
    fn fold(&mut self, key: &Key, cells: &[Cell<u64>]) {
        if cells.iter().all(|c| c.get() == 0) {
            return;
        }
        let totals = self.totals.entry(key.clone()).or_insert_with(|| Totals {
            values: vec![0; key.len()].into(),
            absent_since: None,
        });
        for (total, cell) in totals.values.iter_mut().zip(cells) {
            *total = total.wrapping_add(cell.get());
        }
    }

    /// Drops the totals of labels missing from `current` for [`RETIRE_AFTER`] seconds.
    fn prune(&mut self, current: &Layout, now: u32) {
        self.totals.retain(|key, totals| {
            if current.has(key) {
                totals.absent_since = None;
                return true;
            }
            let since = *totals.absent_since.get_or_insert(now);
            now.wrapping_sub(since) < RETIRE_AFTER
        });
    }

    /// Sums the totals and every live snapshot by label into the scratch.
    fn sum(&mut self) -> &Sums {
        let Retired { totals, live, sums } = self;
        sums.begin();
        for (key, totals) in totals.iter() {
            let values = sums.entry(key);
            for (v, t) in values.iter_mut().zip(totals.values.iter()) {
                *v = v.wrapping_add(*t);
            }
        }
        for (cells, layout) in live.iter() {
            let Some(cells) = cells.upgrade() else {
                continue;
            };
            for (key, at) in layout.series.iter() {
                let at = *at as usize;
                let values = sums.entry(key);
                for (v, c) in values.iter_mut().zip(&cells[at..at + key.len()]) {
                    *v = v.wrapping_add(c.get());
                }
            }
        }
        sums.end();
        sums
    }
}

/// Series values summed by label, kept between ticks so a tick allocates only when the set
/// of labels changes.
#[derive(Default)]
pub(crate) struct Sums {
    pub series: Vec<(Key, Box<[u64]>)>,
    used: Vec<bool>,
    index: HashMap<Key, usize>,
    /// Changes whenever `series` gains or loses a label.
    pub version: u64,
}

impl Sums {
    fn begin(&mut self) {
        for (_, values) in self.series.iter_mut() {
            values.fill(0);
        }
        self.used.fill(false);
    }

    fn entry(&mut self, key: &Key) -> &mut [u64] {
        let i = match self.index.get(key) {
            Some(&i) => i,
            None => {
                let i = self.series.len();
                self.series.push((key.clone(), vec![0; key.len()].into()));
                self.used.push(false);
                self.index.insert(key.clone(), i);
                self.version += 1;
                i
            }
        };
        self.used[i] = true;
        &mut self.series[i].1
    }

    fn end(&mut self) {
        if self.used.iter().all(|&u| u) {
            return;
        }
        let mut used = self.used.iter();
        self.series.retain(|_| *used.next().unwrap_or(&true));
        self.used.retain(|&u| u);
        self.index = self
            .series
            .iter()
            .enumerate()
            .map(|(i, (k, _))| (k.clone(), i))
            .collect();
        self.version += 1;
    }
}

/// Counter cells of one listener.
pub(crate) mod conn {
    pub const ACCEPTED: usize = 0;
    pub const CLOSED: usize = 1;
    pub const HANDSHAKES_OK: usize = 2;
    pub const HANDSHAKES_FAILED: usize = 3;
    pub const LEN: usize = 4;
}

/// Per-connection counters on the `Core`: accepted, closed, and TLS handshakes by result, by
/// listener.
#[derive(Default)]
pub(crate) struct ConnCounters {
    by_listener: RefCell<Vec<(ListenerKey, [Cell<u64>; conn::LEN])>>,
}

impl ConnCounters {
    #[inline]
    fn count(&self, listener: ListenerKey, cell: usize) {
        let mut all = self.by_listener.borrow_mut();
        let cells = match all.iter().position(|(key, _)| *key == listener) {
            Some(i) => &all[i].1,
            None => {
                all.push((listener, Default::default()));
                &all[all.len() - 1].1
            }
        };
        add(&cells[cell], 1);
    }

    /// A connection (TCP) or an incoming QUIC connection was accepted on `listener`.
    #[inline]
    pub fn accepted(&self, listener: ListenerKey) {
        self.count(listener, conn::ACCEPTED);
    }

    /// A connection accepted on `listener` ended.
    #[inline]
    pub fn closed(&self, listener: ListenerKey) {
        self.count(listener, conn::CLOSED);
    }

    /// A TLS handshake on `listener` ended, completed or not.
    #[inline]
    pub fn handshake(&self, listener: ListenerKey, ok: bool) {
        let cell = if ok {
            conn::HANDSHAKES_OK
        } else {
            conn::HANDSHAKES_FAILED
        };
        self.count(listener, cell);
    }

    fn copy_into(&self, out: &mut Vec<(ListenerKey, [u64; conn::LEN])>) {
        out.clear();
        out.extend(
            self.by_listener
                .borrow()
                .iter()
                .map(|(key, cells)| (*key, cells.each_ref().map(Cell::get))),
        );
    }
}

/// What a core's tick hands the hub.
#[derive(Default)]
pub(crate) struct Published {
    pub series: Vec<(Key, Box<[u64]>)>,
    /// The `Sums::version` `series` was copied from.
    version: u64,
    pub conns: Vec<(ListenerKey, [u64; conn::LEN])>,
    /// Per origin label: requests in flight on this core, summed by the scrape.
    pub in_flight: Vec<(Arc<str>, u32)>,
}

/// The core's tick: its totals, live snapshots and connection counters into its hub slot.
/// Allocates only when the set of labels changed since the last tick.
pub(crate) fn publish(core: &crate::runtime::Core) {
    let snap = core.snapshot();
    let Some(counters) = &snap.metrics else {
        return;
    };
    let Some(slot) = counters.hub.cores.get(core.index) else {
        return;
    };
    let mut retired = core.retired.borrow_mut();
    let mut published = slot.lock().unwrap_or_else(|e| e.into_inner());
    retired.publish(&counters.layout, core.clock.mono.get(), &mut published);
    core.connections.copy_into(&mut published.conns);
    published.in_flight.clear();
    let epoch = snap.upstreams.epoch;
    for (i, origin) in snap.upstreams.origins().iter().enumerate() {
        let id = OriginId(i as u16);
        let n = core
            .upstreams
            .local(id, epoch)
            .map_or(0, |local| local.in_flight.get());
        published.in_flight.push((origin.label.clone(), n));
    }
}

impl Retired {
    /// Prunes labels gone from `current`, sums, and copies the sums into `published`.
    pub(super) fn publish(&mut self, current: &Layout, now: u32, published: &mut Published) {
        self.prune(current, now);
        let sums = self.sum();
        if published.version == sums.version && published.series.len() == sums.series.len() {
            for ((_, to), (_, from)) in published.series.iter_mut().zip(sums.series.iter()) {
                to.copy_from_slice(from);
            }
        } else {
            published.series.clone_from(&sums.series);
            published.version = sums.version;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::testing::plan_from;
    use crate::upstream::Registry;

    fn plan() -> Plan {
        plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "sites": [{
                    "name": "a", "hosts": ["*"], "listen": ["127.0.0.1:1"],
                    "routes": [
                        {"name": "scrape", "when": {"path": "/metrics"}, "metrics": {}},
                        {"name": "api", "proxy": "http://127.0.0.1:9000"},
                    ],
                }],
            }),
        )
    }

    fn slot(plan: &Plan, route: &str) -> RouteSlot {
        RouteSlot(plan.routes.iter().position(|l| &*l.route == route).unwrap() as u16)
    }

    fn values<'a>(sums: &'a Sums, key: &Key) -> &'a [u64] {
        &sums.series.iter().find(|(k, _)| k == key).unwrap().1
    }

    #[test]
    fn a_request_lands_in_its_class_and_bucket() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1_000), 0, "le is inclusive");
        assert_eq!(bucket(1_001), 1);
        assert_eq!(bucket(10_000_000), 12);
        assert_eq!(bucket(10_000_001), 13, "+Inf");
        assert_eq!(class(Status::OK), 1);
        assert_eq!(class(Status::NOT_FOUND), 3);
        assert_eq!(class(Status::CONTINUE), 0);
    }

    #[test]
    fn dropped_snapshots_fold_by_label_into_the_core_totals() {
        let plan = plan();
        let upstreams = Registry::new(1).build(&plan);
        let retired = Rc::new(RefCell::new(Retired::default()));
        let api = slot(&plan, "api");
        let key = Key::Route(route_labels("a", "api"));
        let old = Counters::new(
            Layout::build(&plan, &upstreams),
            Hub::new(1),
            retired.clone(),
        );
        old.request(api, Status::OK, Duration::from_micros(1_500));
        let new = Counters::new(
            Layout::build(&plan, &upstreams),
            Hub::new(1),
            retired.clone(),
        );
        new.request(api, Status::BAD_GATEWAY, Duration::from_secs(20));
        {
            let mut r = retired.borrow_mut();
            let v = values(r.sum(), &key);
            assert_eq!(v[route::REQUESTS + 1], 1, "live snapshots count");
            assert_eq!(v[route::REQUESTS + 4], 1);
        }
        drop(old);
        let mut r = retired.borrow_mut();
        assert_eq!(r.live.len(), 1, "a dropped snapshot leaves the live list");
        let v = values(r.sum(), &key);
        assert_eq!(
            (v[route::REQUESTS + 1], v[route::REQUESTS + 4]),
            (1, 1),
            "a dropped snapshot's counts stay"
        );
        assert_eq!(v[route::DURATION + 1], 1);
        assert_eq!(v[route::DURATION + BUCKETS - 1], 1);
        assert_eq!(v[route::DURATION_SUM], 1_500 + 20_000_000);
    }

    #[test]
    fn a_label_missing_from_the_plan_for_ten_minutes_is_pruned() {
        let plan = plan();
        let upstreams = Registry::new(1).build(&plan);
        let other = plan_from(
            2,
            &serde_json::json!({"version": 1, "sites": [{"name": "b", "hosts": ["*"],
                "routes": [{"metrics": {}}]}]}),
        );
        let retired = Rc::new(RefCell::new(Retired::default()));
        let old = Counters::new(
            Layout::build(&plan, &upstreams),
            Hub::new(1),
            retired.clone(),
        );
        old.request(slot(&plan, "api"), Status::OK, Duration::ZERO);
        drop(old);
        let current = Layout::build(&other, &Registry::new(1).build(&other));
        let key = Key::Route(route_labels("a", "api"));
        let mut r = retired.borrow_mut();
        r.prune(&current, 100);
        r.prune(&current, 100 + RETIRE_AFTER - 1);
        assert!(r.totals.contains_key(&key), "kept for ten minutes");
        r.prune(&current, 100 + RETIRE_AFTER);
        assert!(!r.totals.contains_key(&key), "then dropped");
    }

    #[test]
    fn upstream_answers_count_by_class_and_failures_by_cause() {
        let plan = plan();
        let upstreams = Registry::new(1).build(&plan);
        let retired = Rc::new(RefCell::new(Retired::default()));
        let c = Counters::new(
            Layout::build(&plan, &upstreams),
            Hub::new(1),
            retired.clone(),
        );
        c.upstream(OriginId(0), Ok(Status::OK), Duration::from_micros(30));
        c.upstream(OriginId(0), Err(Cause::Timeout), Duration::from_secs(1));
        c.retried(OriginId(0));
        c.upstream(OriginId(9), Ok(Status::OK), Duration::ZERO);
        let mut r = retired.borrow_mut();
        let v = values(r.sum(), &Key::Upstream(origin_labels("127.0.0.1:9000")));
        assert_eq!(v[upstream::RESPONSES + 1], 1);
        assert_eq!(v[upstream::FAILURES + Cause::Timeout.index()], 1);
        assert_eq!(v[upstream::RESPONSE], 1, "failures have no response time");
        assert_eq!(v[upstream::RESPONSE_SUM], 30);
        assert_eq!(v[upstream::RETRIES], 1);
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(
            &*route_labels("a\"b", "c\\d\ne"),
            r#"site="a\"b",route="c\\d\ne""#
        );
    }
}
