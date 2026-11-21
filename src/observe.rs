//! What happens to a request once it is over: its access log line and its metrics. The one
//! place that decides, per request, which of them runs. `access.rs` keeps the line format and
//! the per-core writer; `metrics` keeps the counters.
//!
//! A site that neither logs nor runs under a plan that collects metrics has no `Observe`, and
//! `pipeline::handle` never calls in here.

use crate::access;
use crate::exchange::{ASpan, Exchange, RefusedBy};
use crate::msg::Status;
use crate::plan::{LogId, Observe};
use crate::runtime::{Core, CoreSnapshot, monotonic_nanos};
use std::time::Duration;

/// What the pipeline noted about a request, until the driver finishes it. `Copy` and as small
/// as the access log's record was (32 bytes on Linux): the pipeline future holds it across the
/// proxy's await, and future size costs memmoves per stream. What metrics note about the
/// upstream attempt lives in the exchange instead ([`Upstream`]).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Started {
    /// [`monotonic_nanos`] when the request started.
    at: u64,
    /// The request's fields, formatted into the arena while still as received; empty unless
    /// `log`.
    request: ASpan,
    log: Option<LogId>,
    metrics: bool,
}

/// When a proxied request's first upstream attempt started and when its answer came back, in
/// microseconds after the request started (saturating at about 71 minutes; 0: not proxied, or
/// no answer), and what the answer was. Kept in `Exchange::upstream`, written only while
/// metrics are collected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Upstream {
    pub started_at: u32,
    pub answered_at: u32,
    pub answer: Answer,
}

/// A status, or the cause of a failed last attempt, in two bytes: 0 for no answer, a
/// `metrics::Cause` (1 to 5), or a status code (100 and up).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Answer(u16);

impl Answer {
    fn get(self) -> Option<Result<Status, crate::metrics::Cause>> {
        match crate::metrics::Cause::from_code(self.0) {
            Some(cause) => Some(Err(cause)),
            None => Status::new(self.0).map(Ok),
        }
    }
}

/// One clock read; for a logging site, the request's fields into the arena.
pub(crate) fn start(observe: &Observe, ex: &mut Exchange) -> Started {
    let at = monotonic_nanos();
    let request = match observe.log {
        Some(_) => access::request_fields(ex),
        None => ASpan::default(),
    };
    if observe.metrics {
        ex.upstream = Upstream::default();
    }
    Started {
        at,
        request,
        log: observe.log,
        metrics: observe.metrics,
    }
}

impl Started {
    /// Before `proxy::forward`: a clock read when metrics are collected.
    #[inline]
    pub fn upstream_started(&self, ex: &mut Exchange) {
        if self.metrics {
            ex.upstream.started_at = micros_since(self.at);
        }
    }

    /// After it: a clock read when metrics are collected, and what came back.
    #[inline]
    pub fn upstream_answered(
        &self,
        ex: &mut Exchange,
        answer: Result<Status, crate::metrics::Cause>,
    ) {
        if self.metrics {
            ex.upstream.answered_at = micros_since(self.at);
            ex.upstream.answer = match answer {
                Ok(status) => Answer(status.code()),
                Err(cause) => Answer(cause as u16),
            };
        }
    }
}

/// Microseconds since `at`, saturating at about 71 minutes.
fn micros_since(at: u64) -> u32 {
    (monotonic_nanos().saturating_sub(at) / 1_000).min(u64::from(u32::MAX)) as u32
}

/// Called by the driver once the response or tunnel is over, with what it sent and the
/// snapshot the request ran under. The origin comes from `ex.origin`, the route from
/// `ex.route`, a limit rejection from `ex.refused`.
pub(crate) fn finish(
    core: &Core,
    snap: &CoreSnapshot,
    ex: &Exchange,
    started: Started,
    status: Status,
    bytes: u64,
) {
    let end = monotonic_nanos();
    let took = Duration::from_nanos(end.saturating_sub(started.at));
    if let Some(log) = started.log {
        let line = access::Line {
            ts: core.clock.wall(end),
            request: ex.arena.get(started.request),
            status,
            bytes,
            duration: took,
            upstream: ex.origin.map(|id| &snap.upstreams.origin(id).spec),
        };
        core.access.append(&snap.access, log, |out| line.write(out));
    }
    if started.metrics {
        record_metrics(snap, ex, status, took);
    }
}

/// The metrics half of [`finish`]: the request's series, its rejection by a `limit` step,
/// and its upstream series when it was proxied (`ex.upstream`). Three to eight `Cell` adds.
#[inline]
fn record_metrics(snap: &CoreSnapshot, ex: &Exchange, status: Status, took: Duration) {
    let Some(counters) = &snap.metrics else {
        return;
    };
    counters.request(ex.route, status, took);
    if matches!(ex.refused, Some(r) if r.by == RefusedBy::Limit) {
        counters.limited(ex.route);
    }
    if let (Some(origin), Some(answer)) = (ex.origin, ex.upstream.answer.get()) {
        let took = ex
            .upstream
            .answered_at
            .saturating_sub(ex.upstream.started_at);
        counters.upstream(origin, answer, Duration::from_micros(u64::from(took)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn started_is_no_larger_than_three_words() {
        let size = size_of::<Started>();
        assert!(size <= 24, "observe::Started is {size} bytes");
    }
}
