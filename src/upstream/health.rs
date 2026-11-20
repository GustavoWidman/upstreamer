//! Origin health: the shared cell, passive outcomes, and active probes.
//!
//! Time is the health clock: whole seconds since process start (`runtime::Clock::mono`), so
//! every core compares the same numbers and a wall-clock jump cannot extend an ejection.
//!
//! Passive checks count consecutive failed attempts per core (`OriginLocal::fails`, a `Cell`);
//! the core that reaches `maxFails` ejects the origin for every core. Active checks run on one
//! core per origin (`Origin::probe_core`), which alone writes the probe verdict.

use crate::log::{info, warning};
use crate::msg::{Method, ResponseHead, Status};
use crate::plan::{OriginId, OriginKey, PassivePlan, ProbePlan};
use crate::proto::h1::codec::{self, Limits, Parsed};
use crate::proxy::pool::OriginLocal;
use crate::runtime::Core;
use crate::upstream::{Origin, Upstreams};
use bytes::{Buf, BytesMut};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::IoSlice;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::Instant;

/// Ejections in a row past which the cooldown stops doubling: 8x.
const MAX_DOUBLINGS: u8 = 3;

/// One origin's health, shared by every core and carried across epochs by origin identity.
/// 64-byte aligned: a write (a health transition, rare) invalidates no other origin's line.
#[repr(align(64))]
#[derive(Debug, Default)]
pub(crate) struct Health {
    /// Health-clock second until which passive checks keep the origin out. Written with
    /// `fetch_max` by any core, so concurrent ejections commute and a shorter one never
    /// shortens a longer one.
    ejected_until: AtomicU32,
    /// Consecutive ejections, for the doubling cooldown; reset by the first success once an
    /// ejection is over.
    ejections: AtomicU8,
    /// The last probe verdict. Written only by the origin's probing core.
    probe_down: AtomicBool,
}

impl Health {
    /// Two relaxed loads; no write.
    #[inline]
    pub fn eligible(&self, now: u32) -> bool {
        !self.probe_down.load(Ordering::Relaxed) && !self.ejected(now)
    }

    /// Whether passive checks keep the origin out at `now`. One relaxed load.
    #[inline]
    pub fn ejected(&self, now: u32) -> bool {
        self.ejected_until.load(Ordering::Relaxed) > now
    }

    /// The health-clock second an ejection ends; at or before now when there is none.
    pub fn ejected_until(&self) -> u32 {
        self.ejected_until.load(Ordering::Relaxed)
    }

    pub fn probe_down(&self) -> bool {
        self.probe_down.load(Ordering::Relaxed)
    }

    /// A probe verdict. Called only by the origin's probing core.
    pub(crate) fn set_probe(&self, down: bool) {
        self.probe_down.store(down, Ordering::Relaxed)
    }

    /// Ejects until `now + cooldown * 2^min(ejections, 3)`, unless an ejection is running.
    /// Returns whether this one started: only that one counts toward the doubling, so cores
    /// ejecting the same outage at once double it once.
    fn eject(&self, now: u32, cooldown: u32) -> bool {
        if self.ejected(now) {
            return false;
        }
        let streak = self.ejections.load(Ordering::Relaxed);
        let until = now.saturating_add(cooldown.saturating_mul(1 << streak.min(MAX_DOUBLINGS)));
        let before = self.ejected_until.fetch_max(until, Ordering::Relaxed);
        let fresh = before <= now;
        if fresh {
            self.ejections
                .store(streak.saturating_add(1), Ordering::Relaxed);
        }
        fresh
    }

    /// A success: ends the doubling once the ejection it followed is over. One relaxed load
    /// while nothing was ejected.
    #[inline]
    fn succeeded(&self, now: u32) {
        if self.ejections.load(Ordering::Relaxed) != 0 && !self.ejected(now) {
            self.ejections.store(0, Ordering::Relaxed);
        }
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

/// Records an attempt's outcome on this core. `Answered` clears the core's consecutive
/// failure count (a `Cell` store, skipped when already 0) and, after an ejection is over, the
/// doubling. `Failed` increments the count and, at `max_fails`, ejects the origin for every
/// core and resets the count. Ejection always happens; what happens when every member is
/// ejected is decided in one place, `balance::pick`. Without `passive`, nothing is counted.
#[inline]
pub(crate) fn observe(
    origin: &Origin,
    local: &OriginLocal,
    passive: Option<&PassivePlan>,
    outcome: Outcome,
    now: u32,
) {
    let Some(passive) = passive else {
        return;
    };
    match outcome {
        Outcome::Answered => {
            if local.fails.get() != 0 {
                local.fails.set(0);
            }
            origin.health.succeeded(now);
        }
        Outcome::Failed => {
            let fails = local.fails.get().saturating_add(1);
            if fails < passive.max_fails {
                local.fails.set(fails);
                return;
            }
            local.fails.set(0);
            if origin.health.eject(now, passive.cooldown) {
                let until = origin.health.ejected_until();
                warning!(
                    "origin {}: {fails} failed attempts in a row, out of rotation for {}s",
                    origin.label,
                    until.saturating_sub(now)
                );
            }
        }
        Outcome::Neutral => {}
    }
}

/// Probes running at once on one core, at most.
const MAX_PROBES: usize = 16;

/// The probe loop of one core, spawned next to the pool sweeper. It reads the core's
/// snapshot at least once a second and probes each origin whose `probe_core` is this core and
/// whose interval (shortened by up to 10% at random, so probes of many origins spread out) has
/// passed, at most 16 at a time, each in its own local task: [`crate::proxy::dial`] with the
/// probe timeout (so DNS, TLS and session resumption are the ones requests use), write
/// `ProbePlan::request`, read the head with the h1 codec, close. Consecutive results live
/// here, keyed by identity, so an epoch change keeps them. A verdict change writes
/// `probe_down` and logs once.
pub(crate) async fn probe_loop(core: Rc<Core>) {
    let mut streaks: HashMap<OriginKey, Streak> = HashMap::new();
    let done: Rc<RefCell<Vec<(OriginKey, bool)>>> = Rc::default();
    let running = Rc::new(Cell::new(0usize));
    let mut rng = Rng::seeded(core.index as u64);
    let mut epoch = None;
    loop {
        if core.draining.get() {
            return;
        }
        let snap = core.snapshot();
        let up = &snap.upstreams;
        let now = Instant::now();
        let mut wake = now + Duration::from_secs(1);
        if epoch != Some(up.epoch) {
            epoch = Some(up.epoch);
            let mine: HashMap<OriginKey, &Origin> = up
                .origins()
                .iter()
                .filter(|o| probed_here(&core, o))
                .map(|o| (o.spec.key(), o))
                .collect();
            streaks.retain(|key, _| mine.contains_key(key));
            for (key, origin) in mine {
                streaks
                    .entry(key)
                    .and_modify(|s| s.health = origin.health.clone())
                    .or_insert_with(|| Streak {
                        health: origin.health.clone(),
                        passes: 0,
                        fails: 0,
                        due: now + rng.fraction_of(probe_of(origin).interval),
                        running: false,
                    });
            }
        }
        for (key, passed) in done.borrow_mut().drain(..) {
            let Some(streak) = streaks.get_mut(&key) else {
                continue;
            };
            streak.running = false;
            let Some(origin) = up.origins().iter().find(|o| o.spec.key() == key) else {
                continue;
            };
            if let Some(down) = streak.record(passed, probe_of(origin)) {
                origin.health.set_probe(down);
                if down {
                    warning!(
                        "origin {}: failing its health check, out of rotation",
                        origin.label
                    );
                } else {
                    info!("origin {}: passing its health check again", origin.label);
                }
            }
        }
        for (i, origin) in up.origins().iter().enumerate() {
            if !probed_here(&core, origin) {
                continue;
            }
            let Some(streak) = streaks.get_mut(&origin.spec.key()) else {
                continue;
            };
            if !streak.running && streak.due <= now && running.get() < MAX_PROBES {
                let probe = probe_of(origin);
                streak.running = true;
                streak.due = now + probe.interval - rng.fraction_of(probe.interval / 10);
                running.set(running.get() + 1);
                let (core, up, done, running) =
                    (core.clone(), up.clone(), done.clone(), running.clone());
                let id = OriginId(i as u16);
                tokio::task::spawn_local(async move {
                    let passed = run_probe(&core, &up, id).await;
                    done.borrow_mut().push((up.origin(id).spec.key(), passed));
                    running.set(running.get() - 1);
                });
            }
            if !streak.running {
                wake = wake.min(streak.due);
            }
        }
        drop(snap);
        tokio::time::sleep_until(wake.max(now + Duration::from_millis(10))).await;
    }
}

fn probed_here(core: &Core, origin: &Origin) -> bool {
    origin.spec.probe.is_some() && usize::from(origin.probe_core) == core.index
}

fn probe_of(origin: &Origin) -> &ProbePlan {
    origin
        .spec
        .probe
        .as_ref()
        .expect("only origins with a probe are probed")
}

/// One probe of origin `id`: whether it answered a status in `expect` within the timeout.
async fn run_probe(core: &Core, up: &Upstreams, id: OriginId) -> bool {
    let plan = probe_of(up.origin(id));
    let attempt = async {
        let mut conn = crate::proxy::dial(core, up, id, plan.timeout).await.ok()?;
        conn.io
            .write_all_vectored(&mut [IoSlice::new(&plan.request)])
            .await
            .ok()?;
        let limits = Limits {
            max_head_bytes: 16 * 1024,
            max_header_fields: 128,
        };
        let mut buf = BytesMut::with_capacity(1024);
        let mut head = ResponseHead::new(Status::OK);
        loop {
            match codec::parse_response(&buf, &limits, Method::Get, &mut head) {
                Ok(Parsed::Complete { head_len, .. }) if head.status.code() < 200 => {
                    buf.advance(head_len);
                    continue;
                }
                Ok(Parsed::Complete { .. }) => return Some(plan.expect.contains(head.status)),
                Ok(Parsed::Partial) => {}
                Err(_) => return Some(false),
            }
            if conn.io.read(&mut buf).await.ok()? == 0 {
                return Some(false);
            }
        }
    };
    tokio::time::timeout(plan.timeout, attempt)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// The probing core's record of one origin.
struct Streak {
    health: Arc<Health>,
    /// Consecutive passes and failures; one of them is always 0.
    passes: u8,
    fails: u8,
    due: Instant,
    running: bool,
}

impl Streak {
    /// Counts a result; `Some(down)` when the verdict changes.
    fn record(&mut self, passed: bool, plan: &ProbePlan) -> Option<bool> {
        let down = self.health.probe_down();
        if passed {
            self.fails = 0;
            self.passes = self.passes.saturating_add(1);
            (down && self.passes >= plan.healthy_after).then_some(false)
        } else {
            self.passes = 0;
            self.fails = self.fails.saturating_add(1);
            (!down && self.fails >= plan.unhealthy_after).then_some(true)
        }
    }
}

/// xorshift64* for probe jitter.
struct Rng(u64);

impl Rng {
    fn seeded(core: u64) -> Rng {
        let clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        Rng(super::maglev::mix(core ^ u64::from(clock) << 20) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A uniformly random part of `d`.
    fn fraction_of(&mut self, d: Duration) -> Duration {
        d.mul_f64((self.next() >> 11) as f64 / (1u64 << 53) as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::StatusSet;

    fn origin() -> Origin {
        Origin {
            spec: crate::plan::OriginSpec {
                host: "10.0.0.1".into(),
                port: 80,
                addr: crate::plan::OriginAddr::Ip("10.0.0.1:80".parse().unwrap()),
                tls: None,
                idle: Duration::from_secs(60),
                max_idle_per_core: 4,
                probe: None,
            },
            health: Arc::default(),
            label: "10.0.0.1:80".into(),
            probe_core: 0,
        }
    }

    const PASSIVE: PassivePlan = PassivePlan {
        max_fails: 3,
        cooldown: 10,
    };

    #[test]
    fn max_fails_in_a_row_on_one_core_eject_for_the_cooldown_and_repeats_double_it() {
        let o = origin();
        let core_a = OriginLocal::default();
        let core_b = OriginLocal::default();
        let fail =
            |local: &OriginLocal, now| observe(&o, local, Some(&PASSIVE), Outcome::Failed, now);
        fail(&core_a, 100);
        fail(&core_a, 100);
        observe(&o, &core_a, Some(&PASSIVE), Outcome::Answered, 100);
        fail(&core_a, 100);
        fail(&core_b, 100);
        fail(&core_a, 100);
        assert!(
            o.health.eligible(100),
            "a success breaks the streak; cores count apart"
        );
        fail(&core_a, 100);
        assert!(
            !o.health.eligible(100),
            "third failure in a row on one core"
        );
        assert!(!o.health.eligible(109));
        assert!(o.health.eligible(110), "readmitted after the 10s cooldown");

        for _ in 0..3 {
            fail(&core_a, 110);
        }
        assert!(!o.health.eligible(129));
        assert!(
            o.health.eligible(130),
            "the second ejection in a row lasts 20s"
        );
        for _ in 0..3 {
            fail(&core_b, 130);
        }
        assert!(
            o.health.eligible(170) && !o.health.eligible(169),
            "then 40s"
        );

        observe(&o, &core_a, Some(&PASSIVE), Outcome::Answered, 170);
        for _ in 0..3 {
            fail(&core_a, 200);
        }
        assert!(
            o.health.eligible(210),
            "a success after readmission resets the doubling"
        );
    }

    #[test]
    fn the_doubling_stops_at_eight_times_and_concurrent_ejections_count_once() {
        let o = origin();
        let local = OriginLocal::default();
        let mut now = 0;
        for _ in 0..6 {
            for _ in 0..3 {
                observe(&o, &local, Some(&PASSIVE), Outcome::Failed, now);
            }
            now = o.health.ejected_until();
        }
        let start = now;
        for _ in 0..3 {
            observe(&o, &local, Some(&PASSIVE), Outcome::Failed, start);
        }
        assert_eq!(o.health.ejected_until() - start, 80);

        let o = origin();
        let (a, b) = (OriginLocal::default(), OriginLocal::default());
        for _ in 0..3 {
            observe(&o, &a, Some(&PASSIVE), Outcome::Failed, 0);
            observe(&o, &b, Some(&PASSIVE), Outcome::Failed, 0);
        }
        for _ in 0..3 {
            observe(&o, &a, Some(&PASSIVE), Outcome::Failed, 10);
        }
        assert_eq!(
            o.health.ejected_until(),
            30,
            "two cores ejecting one outage double the next cooldown once"
        );
    }

    #[test]
    fn without_passive_checks_and_for_neutral_outcomes_nothing_is_counted() {
        let o = origin();
        let local = OriginLocal::default();
        for _ in 0..10 {
            observe(&o, &local, None, Outcome::Failed, 0);
            observe(&o, &local, Some(&PASSIVE), Outcome::Neutral, 0);
        }
        assert_eq!(local.fails.get(), 0);
        assert!(o.health.eligible(0));
    }

    #[test]
    fn a_probe_streak_flips_the_verdict_after_its_thresholds() {
        let plan = ProbePlan {
            request: Box::default(),
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            expect: StatusSet::default(),
            healthy_after: 2,
            unhealthy_after: 3,
        };
        let health = Arc::new(Health::default());
        let mut streak = Streak {
            health: health.clone(),
            passes: 0,
            fails: 0,
            due: Instant::now(),
            running: false,
        };
        let mut apply = |passed| {
            let change = streak.record(passed, &plan);
            if let Some(down) = change {
                health.set_probe(down);
            }
            change
        };
        assert_eq!(apply(false), None);
        assert_eq!(apply(false), None);
        assert_eq!(apply(true), None, "a pass breaks the failing streak");
        assert_eq!(apply(false), None);
        assert_eq!(apply(false), None);
        assert_eq!(apply(false), Some(true), "unhealthyAfter = 3");
        assert_eq!(apply(false), None, "already down");
        assert_eq!(apply(true), None);
        assert_eq!(apply(true), Some(false), "healthyAfter = 2");
        assert_eq!(apply(true), None);
    }
}
