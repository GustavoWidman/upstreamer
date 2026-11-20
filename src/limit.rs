//! Rate limits: one table of GCRA states per `limit` step, shared by every core, exact across
//! cores (one compare-and-swap per limited request). A plan without `limit` steps has no
//! table, and no request reaches this module.
//!
//! # Exact across cores
//!
//! A client's requests ride one connection far more often than many, and a connection lives on
//! one core. Per-core buckets with a share of the rate would give that client a fraction of
//! its rate; per-core buckets with the full rate would give a client with many connections
//! `cores` times its rate. So every core admits against the same state.
//!
//! # One word per key
//!
//! GCRA keeps one number per key, the theoretical arrival time (TAT). A slot is one
//! `AtomicU64`: a 24-bit fingerprint of the key's hash in the top bits and a 40-bit TAT in the
//! table's time unit (2^-k seconds, wrapping). Admission is one load of the line and one
//! compare-and-swap on one slot:
//!
//! ```text
//! tat' = max(tat, now) + interval
//! admit  iff  tat' - now <= tolerance        (tolerance = burst x interval)
//! else Retry-After = ceil((tat' - now - tolerance) / 1 s), at least 1
//! ```
//!
//! A refusal writes nothing, so a client that keeps hammering gains nothing and costs nothing.
//!
//! The compiler picks `k` per table: the finest unit that gives an interval 2^14 units while
//! keeping `2 x (tolerance + interval)` within a quarter of the 40-bit range. A TAT is never
//! further ahead of now than `tolerance`, so a slot whose TAT is not within the next
//! `2 x (tolerance + interval)` units is stale, whether it is in the past or has wrapped; it
//! holds exactly the state of a key never seen (a full bucket) and is free to take.
//!
//! # Memory bound and eviction, with no sweeper
//!
//! The table is allocated once (`slots x 8` bytes) when its generation is built. A key's hash
//! picks one 64-byte line of 8 slots. A key takes, in order: the slot that carries its
//! fingerprint, a stale slot, the live slot with the smallest TAT. The last is the key closest
//! to a full bucket, whose loss can only make the limiter more lenient to it, by less than any
//! other choice. Replacements of live slots are counted
//! (`upstreamer_ratelimit_evictions_total`).
//!
//! Two different keys with the same line and fingerprint share a bucket: about 5e-7 per new
//! key with 8 slots a line, and the hash is seeded per table, so a client cannot aim for it.
//!
//! # Cost
//!
//! Per limited request: the key's hash (address octets for `{remote_net}`, no formatting), one
//! monotonic clock read (vDSO), one line load, one CAS (uncontended for per-client keys, whose
//! requests stay on one core). A constant key makes every core CAS one line. Nothing
//! allocates.

use crate::exchange::Exchange;
use crate::plan::{LimitPlan, LimitSpec, Plan};
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// The tables of one generation, by `LimitId`. Built by the control thread; a table whose
/// `LimitSpec` is unchanged across a reload is the same `Arc`, so its buckets survive.
#[derive(Default)]
pub(crate) struct Limiters {
    tables: Box<[Arc<Table>]>,
}

/// One `limit` step's buckets.
pub(crate) struct Table {
    lines: Box<[Line]>,
    /// `lines.len() - 1` (a power of two).
    mask: u64,
    /// Random per table: keys cannot be aimed at a line.
    seed: u64,
    /// The time origin of this table's TATs; carried with the table.
    origin: Instant,
    /// Right shift that turns `nanoseconds x NS_TO_UNIT` into units of 2^-k seconds.
    shift: u32,
    /// Live buckets replaced to make room for a new key.
    pub evictions: AtomicU64,
}

#[repr(align(64))]
struct Line([AtomicU64; SLOTS]);

const SLOTS: usize = 8;
const TAT_BITS: u32 = 40;
const TAT_MASK: u64 = (1 << TAT_BITS) - 1;
const FP_MASK: u64 = (1 << 24) - 1;
/// `2^91 / 10^9`: with the table's shift of `91 - k`, nanoseconds become units of 2^-k s with
/// no division and a relative error below 2^-60.
const NS_TO_UNIT: u128 = (1u128 << 91) / 1_000_000_000;
/// The odd constant that spreads a hash's entropy over its high bits before the line and the
/// fingerprint are cut from it.
const MIX: u64 = 0x9E37_79B9_7F4A_7C15;

/// What a limit step decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    Yes,
    /// Seconds until a request with this key would be admitted, at least 1.
    Wait(u32),
}

impl Limiters {
    /// The tables for `plan`, reusing `previous`'s table for every `LimitSpec` they share.
    pub fn carry(plan: &Plan, previous: Option<(&Plan, &Limiters)>) -> Arc<Limiters> {
        let mut taken = vec![false; previous.map_or(0, |(p, _)| p.limits.len())];
        let tables = plan
            .limits
            .iter()
            .map(|spec| {
                let kept = previous.and_then(|(old, limiters)| {
                    let at = old
                        .limits
                        .iter()
                        .zip(&taken)
                        .position(|(s, &taken)| !taken && s == spec)?;
                    taken[at] = true;
                    limiters.tables.get(at).cloned()
                });
                kept.unwrap_or_else(|| Arc::new(Table::new(spec)))
            })
            .collect();
        Arc::new(Limiters { tables })
    }

    /// Admits or refuses one request. A request whose key expands to nothing is admitted
    /// (no key, no bucket) and is not counted against anyone.
    pub fn admit(&self, limit: &LimitPlan, ex: &mut Exchange) -> Admit {
        let table = &self.tables[usize::from(limit.table.0)];
        let Some(hash) = crate::key::hash(&limit.key, ex, table.seed) else {
            return Admit::Yes;
        };
        table.admit(hash, limit.interval, limit.tolerance)
    }

    pub fn tables(&self) -> &[Arc<Table>] {
        &self.tables
    }
}

impl Table {
    pub fn new(spec: &LimitSpec) -> Table {
        debug_assert!(spec.slots.is_power_of_two() && spec.slots as usize >= SLOTS);
        let lines = (spec.slots as usize / SLOTS).max(1);
        Table {
            lines: (0..lines).map(|_| Line::default()).collect(),
            mask: lines as u64 - 1,
            seed: RandomState::new().hash_one(0x006c_696d_6974_u64),
            origin: Instant::now(),
            shift: 91 - u32::from(spec.unit_shift),
            evictions: AtomicU64::new(0),
        }
    }

    /// The GCRA step on the line of `hash`. Lock-free; retries its CAS while another core
    /// changes the same slot.
    fn admit(&self, hash: u64, interval: u64, tolerance: u64) -> Admit {
        self.admit_with(hash, interval, tolerance, || {
            self.units(
                Instant::now()
                    .saturating_duration_since(self.origin)
                    .as_nanos() as u64,
            )
        })
    }

    /// [`Table::admit`] at a given `now`, in the table's units modulo 2^40.
    #[cfg(test)]
    fn admit_at(&self, hash: u64, now: u64, interval: u64, tolerance: u64) -> Admit {
        self.admit_with(hash, interval, tolerance, || now)
    }

    /// The GCRA step, reading the clock after the line: a thread that stalls before the
    /// compare-and-swap then fails it (the slot moved on) instead of rewinding the arrival
    /// time with an old reading. A stall between the load and the clock only makes `now`
    /// later, which the unchanged slot allows.
    #[inline(always)]
    fn admit_with(
        &self,
        hash: u64,
        interval: u64,
        tolerance: u64,
        clock: impl Fn() -> u64,
    ) -> Admit {
        let mixed = hash.wrapping_mul(MIX);
        let line = &self.lines[((mixed >> 32) & self.mask) as usize];
        let fingerprint = (mixed >> 8) & FP_MASK;
        let reach = 2 * (tolerance + interval) as i64;
        loop {
            let mut words = [0u64; SLOTS];
            for (word, slot) in words.iter_mut().zip(&line.0) {
                *word = slot.load(Relaxed);
            }
            let now = clock();
            let mut found = None;
            let mut free = None;
            let mut oldest: Option<(usize, i64)> = None;
            for (i, &word) in words.iter().enumerate() {
                let ahead = ahead(word, now);
                let live = ahead > 0 && ahead <= reach;
                if found.is_none() && word >> TAT_BITS == fingerprint {
                    found = Some((i, if live { ahead } else { 0 }));
                } else if !live {
                    free = free.or(Some(i));
                } else if oldest.is_none_or(|(_, least)| ahead < least) {
                    oldest = Some((i, ahead));
                }
            }
            let (slot, held, evicts) = match (found, free, oldest) {
                (Some((i, ahead)), _, _) => (i, ahead, false),
                (None, Some(i), _) => (i, 0, false),
                (None, None, Some((i, _))) => (i, 0, true),
                (None, None, None) => unreachable!("a line has slots"),
            };
            let after = held + interval as i64;
            if after > tolerance as i64 {
                let excess = (after - tolerance as i64) as u64;
                let seconds = excess.div_ceil(1 << self.unit_shift());
                return Admit::Wait(seconds.clamp(1, u64::from(u32::MAX)) as u32);
            }
            let word = fingerprint << TAT_BITS | (now.wrapping_add(after as u64) & TAT_MASK);
            if line.0[slot]
                .compare_exchange_weak(words[slot], word, Relaxed, Relaxed)
                .is_ok()
            {
                if evicts {
                    self.evictions.fetch_add(1, Relaxed);
                }
                return Admit::Yes;
            }
        }
    }

    /// Nanoseconds since the origin as units of 2^-k seconds, modulo 2^40.
    fn units(&self, nanos: u64) -> u64 {
        ((u128::from(nanos) * NS_TO_UNIT) >> self.shift) as u64 & TAT_MASK
    }

    /// `k` of the unit 2^-k seconds.
    fn unit_shift(&self) -> u32 {
        91 - self.shift
    }
}

/// Units from `now` to the TAT in `word`, negative when it is in the past: the 40-bit
/// difference, sign-extended.
fn ahead(word: u64, now: u64) -> i64 {
    ((word.wrapping_sub(now) & TAT_MASK) << (64 - TAT_BITS)) as i64 >> (64 - TAT_BITS)
}

impl Default for Line {
    fn default() -> Line {
        Line(std::array::from_fn(|_| AtomicU64::new(0)))
    }
}

/// Entry points for `benches/limit.rs`; not part of the API.
#[cfg(feature = "internals")]
pub mod bench {
    use super::*;
    use crate::exchange::{ConnInfo, Proto, Scheme};
    use crate::plan::{KeyPlan, LimitId, ListenerKey, ListenerKind, RouteSlot};
    use std::net::{IpAddr, Ipv4Addr};

    /// A limit step that admits everything the benchmark sends it: 10^6 requests a second with
    /// a burst of 2^32 - 1 outlasts any run.
    pub struct Fixture {
        limiters: Arc<Limiters>,
        plan: Arc<LimitPlan>,
    }

    /// The key a lane limits by.
    #[derive(Clone, Copy)]
    pub enum Key {
        /// `{remote_host}`: every client its own bucket.
        PerClient,
        /// One bucket for everyone.
        Constant,
    }

    /// One core's view: its own exchange over the shared tables.
    pub struct Lane {
        limiters: Arc<Limiters>,
        plan: Arc<LimitPlan>,
        ex: Exchange,
    }

    impl Fixture {
        pub fn new(key: Key) -> Fixture {
            let spec = LimitSpec {
                site: "bench".into(),
                step: "/limit".into(),
                key: "".into(),
                slots: match key {
                    Key::PerClient => 65536,
                    Key::Constant => 8,
                },
                unit_shift: 20,
            };
            let interval = 1;
            let plan = Arc::new(LimitPlan {
                table: LimitId(0),
                key: match key {
                    Key::PerClient => KeyPlan::RemoteHost,
                    Key::Constant => KeyPlan::Const(crate::key::constant(b"all")),
                },
                interval,
                tolerance: interval * u64::from(u32::MAX),
                route: RouteSlot(0),
            });
            let limiters = Arc::new(Limiters {
                tables: Box::new([Arc::new(Table::new(&spec))]),
            });
            Fixture { limiters, plan }
        }

        pub fn lane(&self) -> Lane {
            let conn = ConnInfo {
                remote: "192.0.2.1:5000".parse().unwrap(),
                local_port: 80,
                scheme: Scheme::Http,
                proto: Proto::H1,
                listener: ListenerKey {
                    addr: "0.0.0.0:80".parse().unwrap(),
                    kind: ListenerKind::Http,
                },
            };
            Lane {
                limiters: self.limiters.clone(),
                plan: self.plan.clone(),
                ex: Exchange::new(conn, 0),
            }
        }
    }

    impl Lane {
        /// One admission for the client numbered `client`.
        pub fn admit(&mut self, client: u32) -> bool {
            self.ex.client = IpAddr::V4(Ipv4Addr::from(client));
            self.limiters.admit(&self.plan, &mut self.ex) == Admit::Yes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{ConnInfo, Proto, Scheme};
    use crate::plan::{Action, KeyPlan, LimitId, ListenerKey, ListenerKind, RouteSlot};
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::time::Duration;

    fn spec(slots: u32, unit_shift: u8) -> LimitSpec {
        LimitSpec {
            site: "a".into(),
            step: "/sites/0/routes/0/limit".into(),
            key: "{remote_net}".into(),
            slots,
            unit_shift,
        }
    }

    fn exchange(client: &str) -> Exchange {
        let conn = ConnInfo {
            remote: "192.0.2.1:5000".parse().unwrap(),
            local_port: 80,
            scheme: Scheme::Http,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: "0.0.0.0:80".parse().unwrap(),
                kind: ListenerKind::Http,
            },
        };
        let mut ex = Exchange::new(conn, 0);
        ex.client = client.parse().unwrap();
        ex.req
            .set_line(b"GET", b"/", crate::msg::Version::Http11)
            .unwrap();
        ex
    }

    /// `n` hashes that land on one line with different fingerprints.
    fn colliding(table: &Table, n: usize) -> Vec<u64> {
        let place = |hash: u64| {
            let mixed = hash.wrapping_mul(MIX);
            ((mixed >> 32) & table.mask, (mixed >> 8) & FP_MASK)
        };
        let mut found: Vec<(u64, u64)> = Vec::new();
        for hash in 0u64.. {
            let (line, fp) = place(hash);
            if line == 0 && found.iter().all(|&(_, f)| f != fp) {
                found.push((hash, fp));
                if found.len() == n {
                    break;
                }
            }
        }
        found.into_iter().map(|(h, _)| h).collect()
    }

    /// The textbook algorithm, in f64 and without packing: one unbounded TAT per key.
    struct Reference {
        tats: HashMap<u64, f64>,
        interval: f64,
        tolerance: f64,
        unit: f64,
    }

    impl Reference {
        fn admit(&mut self, key: u64, now: f64) -> Admit {
            let tat = self.tats.get(&key).copied().unwrap_or(f64::MIN).max(now);
            let after = tat + self.interval;
            if after - now > self.tolerance {
                let wait = ((after - now - self.tolerance) / self.unit).ceil().max(1.0);
                return Admit::Wait(wait as u32);
            }
            self.tats.insert(key, after);
            Admit::Yes
        }
    }

    proptest! {
        #[test]
        fn admission_matches_the_reference_gcra(
            interval in 1u64..5000,
            burst in 1u64..20,
            unit_shift in 0u8..30,
            start in 0u64..1 << 41,
            arrivals in prop::collection::vec((0u64..4, prop_oneof![
                9 => 0u64..3000,
                1 => 0u64..1 << 34,
            ]), 1..200),
        ) {
            let table = Table::new(&spec(64, unit_shift));
            let hashes = colliding(&table, 4);
            let tolerance = interval * burst;
            let mut reference = Reference {
                tats: HashMap::new(),
                interval: interval as f64,
                tolerance: tolerance as f64,
                unit: f64::from(1u32 << unit_shift),
            };
            let mut now = start;
            for (key, gap) in arrivals {
                now += gap;
                let want = reference.admit(key, now as f64);
                let got = table.admit_at(hashes[key as usize], now & TAT_MASK, interval, tolerance);
                prop_assert_eq!(got, want, "key {} at {}", key, now);
            }
            prop_assert_eq!(table.evictions.load(Relaxed), 0);
        }
    }

    #[test]
    fn a_burst_of_two_at_one_a_second_refuses_the_third_for_a_second() {
        let table = Table::new(&spec(8, 10));
        let (interval, tolerance) = (1024, 2048);
        let h = 7;
        assert_eq!(table.admit_at(h, 0, interval, tolerance), Admit::Yes);
        assert_eq!(table.admit_at(h, 0, interval, tolerance), Admit::Yes);
        assert_eq!(table.admit_at(h, 0, interval, tolerance), Admit::Wait(1));
        assert_eq!(
            table.admit_at(h, 500, interval, tolerance),
            Admit::Wait(1),
            "half a second later it still waits for the rest of the interval"
        );
        assert_eq!(table.admit_at(h, 1024, interval, tolerance), Admit::Yes);
        assert_eq!(table.admit_at(h, 1024, interval, tolerance), Admit::Wait(1));
        assert_eq!(
            table.admit_at(h, 1024 + 5 * 1024, interval, tolerance),
            Admit::Yes,
            "idle time refills the bucket"
        );
    }

    #[test]
    fn a_long_wait_is_reported_in_whole_seconds_rounded_up() {
        let table = Table::new(&spec(8, 10));
        // 1 per minute, burst 1.
        let (interval, tolerance) = (60 * 1024, 60 * 1024);
        assert_eq!(table.admit_at(3, 0, interval, tolerance), Admit::Yes);
        assert_eq!(table.admit_at(3, 0, interval, tolerance), Admit::Wait(60));
        assert_eq!(
            table.admit_at(3, 1024 * 20 + 1, interval, tolerance),
            Admit::Wait(40)
        );
    }

    #[test]
    fn a_refusal_changes_nothing() {
        let table = Table::new(&spec(8, 10));
        let (interval, tolerance) = (1024, 1024);
        assert_eq!(table.admit_at(1, 0, interval, tolerance), Admit::Yes);
        for _ in 0..1000 {
            assert_eq!(table.admit_at(1, 100, interval, tolerance), Admit::Wait(1));
        }
        assert_eq!(
            table.admit_at(1, 1024, interval, tolerance),
            Admit::Yes,
            "hammering did not push the next admission back"
        );
    }

    #[test]
    fn a_slot_idle_for_longer_than_the_clock_wraps_is_a_full_bucket() {
        let table = Table::new(&spec(8, 10));
        let (interval, tolerance) = (1024, 4096);
        for _ in 0..4 {
            assert_eq!(table.admit_at(9, 10, interval, tolerance), Admit::Yes);
        }
        assert_eq!(table.admit_at(9, 10, interval, tolerance), Admit::Wait(1));
        // After 2^39 + 100 idle units the 40-bit difference to the old TAT reads as a TAT far
        // in the future, which no bucket can hold.
        let later = (10 + (1 << 39) + 100) & TAT_MASK;
        let mut admitted = 0;
        while table.admit_at(9, later, interval, tolerance) == Admit::Yes {
            admitted += 1;
        }
        assert_eq!(admitted, 4, "a full bucket");
    }

    #[test]
    fn the_smallest_tat_is_replaced_when_every_slot_of_a_line_is_live() {
        let table = Table::new(&spec(8, 10));
        let keys = colliding(&table, 9);
        let (interval, tolerance) = (1000, 2000);
        for (i, &key) in keys[..8].iter().enumerate() {
            assert_eq!(
                table.admit_at(key, 10 + i as u64, interval, tolerance),
                Admit::Yes
            );
        }
        assert_eq!(table.evictions.load(Relaxed), 0);
        let fingerprints = |table: &Table| -> Vec<u64> {
            table.lines[0]
                .0
                .iter()
                .map(|s| s.load(Relaxed) >> TAT_BITS)
                .collect()
        };
        let before = fingerprints(&table);
        assert_eq!(table.admit_at(keys[8], 30, interval, tolerance), Admit::Yes);
        assert_eq!(table.evictions.load(Relaxed), 1);
        let after = fingerprints(&table);
        let changed: Vec<usize> = (0..8).filter(|&i| before[i] != after[i]).collect();
        assert_eq!(
            changed.len(),
            1,
            "one slot changed: {before:?} -> {after:?}"
        );
        // keys[0] arrived first, so its TAT was the smallest: it is the one that lost its state.
        assert!(
            !after.contains(&before[changed[0]]),
            "the replaced key is gone from the line"
        );
        assert_eq!(
            table.admit_at(keys[0], 31, interval, tolerance),
            Admit::Yes,
            "the evicted key starts with a full bucket"
        );
        assert_eq!(table.admit_at(keys[0], 31, interval, tolerance), Admit::Yes);
        assert_eq!(
            table.admit_at(keys[7], 31, interval, tolerance),
            Admit::Yes,
            "a kept key used one of its two"
        );
        assert_eq!(
            table.admit_at(keys[7], 31, interval, tolerance),
            Admit::Wait(1),
            "and has one left"
        );
    }

    #[test]
    fn stale_slots_are_taken_before_live_ones_are_evicted() {
        let table = Table::new(&spec(8, 10));
        let keys = colliding(&table, 10);
        let (interval, tolerance) = (1000, 2000);
        for (i, &key) in keys[..8].iter().enumerate() {
            table.admit_at(key, 10 + i as u64, interval, tolerance);
        }
        // Every TAT is now in the past: all eight slots are free to take.
        for &key in &keys[8..] {
            assert_eq!(
                table.admit_at(key, 100_000, interval, tolerance),
                Admit::Yes
            );
        }
        assert_eq!(table.evictions.load(Relaxed), 0);
    }

    /// Admissions over `run` by one thread per entry of `keys` (equal entries share a bucket),
    /// against the allowance: never more than `burst + rate x run`, and no fewer than that less
    /// `idle` of it for time a starved thread asked for nothing.
    fn hammer(keys: Vec<u64>, rate_per_second: u64, burst: u64, run: Duration, idle: f64) {
        // Spinning threads starve the core threads of tests that count allocations.
        let _quiet = crate::runtime::testing::raising_signals();
        let unit_shift = 30;
        let interval = ((1u64 << unit_shift) + rate_per_second / 2) / rate_per_second;
        let tolerance = interval * burst;
        let table = Table::new(&spec(64, unit_shift));
        let start = Instant::now();
        let deadline = start + run;
        let admitted: Vec<u64> = std::thread::scope(|scope| {
            let handles: Vec<_> = keys
                .iter()
                .map(|&key| {
                    let table = &table;
                    scope.spawn(move || {
                        let mut admitted = 0;
                        loop {
                            let now = Instant::now();
                            if now >= deadline {
                                return admitted;
                            }
                            if table.admit(key, interval, tolerance) == Admit::Yes {
                                admitted += 1;
                            }
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let seconds = run.as_secs_f64();
        let allowed = burst as f64 + rate_per_second as f64 * seconds;
        let per_key = if keys.iter().all(|&k| k == keys[0]) {
            vec![admitted.iter().sum::<u64>()]
        } else {
            admitted
        };
        for total in per_key {
            let total = total as f64;
            assert!(
                total <= allowed + 1.0,
                "{total} admitted, allowed {allowed}"
            );
            assert!(
                total >= allowed - 2.0 - allowed * idle,
                "{total} admitted, expected {allowed}"
            );
        }
    }

    #[test]
    fn four_threads_on_one_key_get_the_burst_plus_the_rate_and_no_more() {
        let table = Table::new(&spec(64, 24));
        let key = colliding(&table, 1)[0];
        hammer(vec![key; 4], 100, 20, Duration::from_secs(2), 0.05);
    }

    #[test]
    fn four_threads_on_one_key_at_a_high_rate_lose_and_double_no_admission() {
        let table = Table::new(&spec(64, 24));
        let key = colliding(&table, 1)[0];
        hammer(vec![key; 4], 20_000, 2_000, Duration::from_secs(2), 0.05);
    }

    #[test]
    fn four_clients_on_four_threads_each_get_their_own_allowance() {
        let table = Table::new(&spec(64, 24));
        let keys = colliding(&table, 4);
        hammer(keys, 100, 20, Duration::from_secs(2), 0.05);
    }

    #[test]
    fn real_time_converts_to_the_tables_unit() {
        for k in [0u8, 10, 24, 38] {
            let table = Table::new(&spec(8, k));
            for seconds in [1u64, 90, 3600] {
                let units = table.units(seconds * 1_000_000_000);
                let want = (u128::from(seconds) << k) as u64 & TAT_MASK;
                let off = ahead(units, want).abs();
                assert!(
                    off <= 1,
                    "{seconds} s is {units} units of 2^-{k} s, wanted {want}"
                );
            }
        }
    }

    #[test]
    fn a_reload_keeps_the_buckets_of_an_unchanged_spec_and_resets_a_changed_one() {
        use crate::runtime::testing::plan_from;
        let plan = |rate: &str, key: &str| {
            plan_from(
                1,
                &serde_json::json!({
                    "version": 1,
                    "sites": [{ "name": "a", "hosts": ["a.example"], "routes": [
                        { "limit": { "rate": rate, "burst": 2, "key": key } },
                        { "limit": { "rate": "1/h", "burst": 1, "key": "{remote_host}" } },
                        { "respond": {} },
                    ]}],
                }),
            )
        };
        fn limit_of(plan: &Plan, i: usize) -> &LimitPlan {
            let Action::Limit(limit) = &plan.sites[0].routes.steps[i].action else {
                panic!("a limit step");
            };
            limit
        }
        let first = plan("1/h", "{header.x-key}");
        let limiters = Limiters::carry(&first, None);
        let (a, b) = (limit_of(&first, 0), limit_of(&first, 1));
        let mut ex = exchange("192.0.2.9");
        ex.req.push_field(b"X-Key", b"k");
        assert_eq!(limiters.admit(a, &mut ex), Admit::Yes);
        assert_eq!(limiters.admit(a, &mut ex), Admit::Yes);
        assert_eq!(limiters.admit(a, &mut ex), Admit::Wait(3600));
        assert_eq!(limiters.admit(b, &mut ex), Admit::Yes);
        assert_eq!(limiters.admit(b, &mut ex), Admit::Wait(3600));

        let same = plan("1/h", "{header.x-key}");
        let carried = Limiters::carry(&same, Some((&first, &limiters)));
        assert!(Arc::ptr_eq(&carried.tables()[0], &limiters.tables()[0]));
        assert!(Arc::ptr_eq(&carried.tables()[1], &limiters.tables()[1]));
        let (a, b) = (limit_of(&same, 0), limit_of(&same, 1));
        assert!(
            matches!(carried.admit(a, &mut ex), Admit::Wait(_)),
            "the bucket was still empty after the reload"
        );
        assert!(matches!(carried.admit(b, &mut ex), Admit::Wait(_)));

        let other_key = plan("1/h", "{header.x-other}");
        let reset = Limiters::carry(&other_key, Some((&first, &limiters)));
        assert!(!Arc::ptr_eq(&reset.tables()[0], &limiters.tables()[0]));
        assert!(Arc::ptr_eq(&reset.tables()[1], &limiters.tables()[1]));
        let mut ex = exchange("192.0.2.9");
        ex.req.push_field(b"X-Other", b"k");
        assert_eq!(reset.admit(limit_of(&other_key, 0), &mut ex), Admit::Yes);

        let other_unit = plan("5/s", "{header.x-key}");
        let reset = Limiters::carry(&other_unit, Some((&first, &limiters)));
        assert!(
            !Arc::ptr_eq(&reset.tables()[0], &limiters.tables()[0]),
            "a table in another time unit cannot read the old arrival times"
        );
    }

    #[test]
    fn a_request_without_a_key_is_admitted_and_costs_no_one() {
        let limiters = Limiters {
            tables: Box::new([Arc::new(Table::new(&spec(8, 10)))]),
        };
        let mut vars = Vec::new();
        let mut scope = crate::plan::template::Scope {
            vars: &mut vars,
            captures: crate::plan::template::Captures::Unavailable,
            in_error_route: false,
            uses_captures: false,
            reads: Vec::new(),
        };
        let key = KeyPlan::Template(
            crate::plan::template::Template::parse("{header.x-key}", &mut scope).unwrap(),
        );
        let limit = LimitPlan {
            table: LimitId(0),
            key,
            interval: 1024,
            tolerance: 1024,
            route: RouteSlot(0),
        };
        let mut ex = exchange("192.0.2.1");
        for _ in 0..10 {
            assert_eq!(limiters.admit(&limit, &mut ex), Admit::Yes);
        }
    }

    #[test]
    fn remote_net_groups_an_ipv6_64_and_keeps_addresses_of_other_networks_apart() {
        let limiters = Limiters {
            tables: Box::new([Arc::new(Table::new(&spec(64, 10)))]),
        };
        let limit = LimitPlan {
            table: LimitId(0),
            key: KeyPlan::RemoteNet,
            interval: 3600 * 1024,
            tolerance: 3600 * 1024,
            route: RouteSlot(0),
        };
        let admit = |client: &str| limiters.admit(&limit, &mut exchange(client));
        assert_eq!(admit("2001:db8:1:2::1"), Admit::Yes);
        assert_eq!(
            admit("2001:db8:1:2:ffff:ffff:ffff:ffff"),
            Admit::Wait(3600),
            "another address of the same /64 shares the bucket"
        );
        assert_eq!(
            admit("2001:db8:1:3::1"),
            Admit::Yes,
            "the next /64 does not"
        );
        assert_eq!(admit("192.0.2.1"), Admit::Yes);
        assert_eq!(
            admit("192.0.2.2"),
            Admit::Yes,
            "IPv4 hosts have a bucket each"
        );
        assert_eq!(admit("192.0.2.1"), Admit::Wait(3600));
    }

    #[test]
    fn a_limited_request_allocates_nothing_after_warm_up() {
        use crate::runtime::testing::{
            connect, free_addr, no_signals, plan_from, read_response, served,
        };
        use crate::runtime::{Generation, allowed_cpus, spawn_workers, stop};
        use std::io::Write;
        let listen = free_addr();
        let plan = plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": [listen], "https": [] },
                "sites": [{
                    "name": "limited",
                    "hosts": ["*"],
                    "routes": [
                        { "limit": { "rate": "1/h", "burst": 1, "key": "{header.x-client}" } },
                        { "respond": { "body": "ok" } },
                    ],
                    "errors": [{ "status": [429], "routes": [
                        { "respond": { "status": 429, "body": "slow down {err.retry_after}" } },
                    ]}],
                }],
            }),
        );
        let generation = Arc::new(Generation::standalone(plan, None, Arc::default()));
        let workers = spawn_workers(&[allowed_cpus()[0]], generation).unwrap();
        let mut conn = connect(listen);
        let mut request = || {
            conn.write_all(b"GET / HTTP/1.1\r\nHost: test\r\nX-Client: 203.0.113.7\r\n\r\n")
                .unwrap();
            read_response(&mut conn).unwrap()
        };
        let (head, _) = request();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        for _ in 0..2_000 {
            let (head, body) = request();
            assert!(head.starts_with("HTTP/1.1 429 "), "{head}");
            assert!(head.contains("\r\nretry-after: "), "{head}");
            assert!(body.starts_with(b"slow down "), "{body:?}");
        }
        let signals = no_signals();
        let before = served(listen.port(), 0).allocations;
        let requests = 20_000;
        for _ in 0..requests {
            request();
        }
        let after = served(listen.port(), 0).allocations;
        drop(signals);
        stop(workers, Instant::now());
        println!(
            "core thread allocations over {requests} limited keep-alive requests: {}",
            after - before
        );
        assert_eq!(after - before, 0, "allocations on the core thread");
    }
}
