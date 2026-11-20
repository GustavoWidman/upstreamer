//! Choosing an origin for one attempt. Reads the pool's policy (plan), its members and tables
//! (`Upstreams`), each candidate's `Health` (relaxed loads), and this core's counters
//! (`proxy::pool::Pools`: requests in flight per origin); writes only this core's cursor and
//! random state, both `Cell`s. No lock, no read-modify-write, no shared write.
//!
//! Costs per pick (n members, all healthy): round robin O(1); hash O(1) plus the key's hash;
//! p2c O(1); least requests O(n), so p2c is the better choice above a few dozen members.

use crate::exchange::Exchange;
use crate::plan::{BalancePlan, OriginId, PoolPlan};
use crate::proxy::pool::Pools;
use crate::upstream::maglev::mix;
use crate::upstream::{Members, Select, Upstreams};
use smallvec::SmallVec;
use std::cell::Cell;

/// Origins earlier attempts of this request used. A retry prefers any other eligible origin;
/// when none is left, it may reuse one (a pool of one retries its own origin on a fresh
/// connection).
pub(crate) type Tried = SmallVec<[OriginId; 4]>;

/// Per-core state of one pool, indexed by `PoolId` of the core's current plan.
#[derive(Default)]
pub(crate) struct PoolLocal {
    /// Position in the pool's sequence (or member list, for least requests). Starts at a
    /// random position so cores do not walk in lockstep.
    pub cursor: Cell<u32>,
    /// xorshift64* state for p2c; never 0.
    pub rng: Cell<u64>,
}

impl PoolLocal {
    pub fn seeded(seed: u64) -> PoolLocal {
        let state = mix(seed) | 1;
        PoolLocal {
            cursor: Cell::new((state >> 32) as u32),
            rng: Cell::new(state),
        }
    }

    #[inline]
    fn random(&self) -> u64 {
        let mut x = self.rng.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng.set(x);
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// Which members a pass may pick. Passes run in order until one finds a member:
/// 1. probe up, not ejected, not tried by this request;
/// 2. probe up, not ejected (a retry reuses an origin when no other is left);
/// 3. and 4. the same with ejections ignored. These run only when passive checks have
///    ejected every member whose probe is up: an outage of every origin at once is more
///    likely a shared cause (a deploy, the network) than every origin broken, and refusing
///    all traffic would turn a blip into an outage.
#[derive(Clone, Copy)]
struct Pass {
    ejected_ok: bool,
    tried_ok: bool,
}

const PASSES: [Pass; 4] = [
    Pass {
        ejected_ok: false,
        tried_ok: false,
    },
    Pass {
        ejected_ok: false,
        tried_ok: true,
    },
    Pass {
        ejected_ok: true,
        tried_ok: false,
    },
    Pass {
        ejected_ok: true,
        tried_ok: true,
    },
];

/// The view of one pick: who may be chosen.
struct Candidates<'a> {
    members: &'a Members,
    upstreams: &'a Upstreams,
    tried: &'a Tried,
    now: u32,
}

impl Candidates<'_> {
    /// Whether member `i` (an index into `members.origins`) may be picked in `pass`.
    #[inline]
    fn ok(&self, i: u16, pass: Pass) -> bool {
        let id = self.members.origins[usize::from(i)];
        let health = &self.upstreams.origin(id).health;
        if health.probe_down() || (!pass.ejected_ok && health.ejected(self.now)) {
            return false;
        }
        pass.tried_ok || !self.tried.contains(&id)
    }
}

/// The origin for the next attempt, or `None` when no member may be picked: every member is
/// failing its probe or drained, or the pool is empty (a source that never reported).
///
/// Eligible = weight > 0, probe not down, not passively ejected (see [`Pass`] for what
/// happens when that leaves nothing). Policies:
/// - RoundRobin: the next eligible entry of the weighted sequence from this core's cursor.
/// - LeastRequests: the eligible member with the fewest requests in flight on this core per
///   unit of weight (cross-multiplied, no division), ties to the first from the cursor.
/// - P2c: two members drawn by weight; the eligible one with fewer in flight per weight wins.
/// - Hash(key): the key's 64-bit hash (fixed seed: the same key picks the same origin on
///   every core, across restarts, and on every replica with the same members) indexes the
///   Maglev table; an ineligible or already-tried pick probes seven more slots derived from
///   the hash, then falls back to round robin. A request without a key is round robin.
#[allow(clippy::too_many_arguments)]
#[inline]
pub(crate) fn pick(
    pool: &PoolPlan,
    members: &Members,
    upstreams: &Upstreams,
    local: &Pools,
    state: &PoolLocal,
    ex: &mut Exchange,
    tried: &Tried,
    now: u32,
) -> Option<OriginId> {
    let c = Candidates {
        members,
        upstreams,
        tried,
        now,
    };
    let index = match (&pool.balance, &members.select) {
        (BalancePlan::Hash(key), Select::Maglev { table, fallback }) => {
            match crate::key::hash(key, ex, crate::key::FIXED_SEED) {
                Some(hash) => hashed(&c, table, hash).or_else(|| sequence(&c, state, fallback)),
                None => sequence(&c, state, fallback),
            }
        }
        (BalancePlan::P2c, Select::Sequence(seq)) => p2c(&c, local, state, seq),
        (BalancePlan::LeastRequests, _) => least(&c, local, state),
        (_, Select::Sequence(seq)) => sequence(&c, state, seq),
        (_, Select::Maglev { fallback, .. }) => sequence(&c, state, fallback),
        (_, Select::Weights) => least(&c, local, state),
    }?;
    Some(members.origins[usize::from(index)])
}

/// Round robin over a weighted sequence, in [`PASSES`] order.
#[inline]
fn sequence(c: &Candidates<'_>, state: &PoolLocal, seq: &[u16]) -> Option<u16> {
    let n = seq.len();
    if n == 0 {
        return None;
    }
    let mut cursor = state.cursor.get() as usize;
    if cursor >= n {
        cursor %= n;
    }
    for pass in PASSES {
        let mut at = cursor;
        for _ in 0..n {
            let i = seq[at];
            at += 1;
            if at == n {
                at = 0;
            }
            if c.ok(i, pass) {
                state.cursor.set(at as u32);
                return Some(i);
            }
        }
    }
    None
}

/// Requests in flight per unit of weight: whether `a` is strictly less loaded than `b`.
#[inline]
fn lighter(a: (u32, u16), b: (u32, u16)) -> bool {
    u64::from(a.0) * u64::from(b.1) < u64::from(b.0) * u64::from(a.1)
}

#[inline]
fn p2c(c: &Candidates<'_>, local: &Pools, state: &PoolLocal, seq: &[u16]) -> Option<u16> {
    let n = seq.len() as u64;
    if n < 2 {
        return sequence(c, state, seq);
    }
    let r = state.random();
    let draw = |bits: u64, n: u64| (((bits & 0xffff_ffff) * n) >> 32) as usize;
    let at = draw(r, n);
    let a = seq[at];
    // The second draw is among the other positions, so a pair is two distinct entries; a
    // heavy member can hold several, so look on for another member if it drew a itself.
    let len = seq.len();
    let from = at + 1 + draw(r >> 32, n - 1);
    let b = (0..len - 1)
        .map(|k| seq[(from + k) % len])
        .find(|&x| x != a)
        .unwrap_or(a);
    let pass = PASSES[0];
    let (ok_a, ok_b) = (c.ok(a, pass), b != a && c.ok(b, pass));
    match (ok_a, ok_b) {
        (true, true) => {
            let epoch = c.upstreams.epoch;
            let load = |i: u16| {
                (
                    local.in_flight(c.members.origins[usize::from(i)], epoch),
                    c.members.weights[usize::from(i)],
                )
            };
            Some(if lighter(load(b), load(a)) { b } else { a })
        }
        (true, false) => Some(a),
        (false, true) => Some(b),
        (false, false) => sequence(c, state, seq),
    }
}

fn least(c: &Candidates<'_>, local: &Pools, state: &PoolLocal) -> Option<u16> {
    let n = c.members.origins.len();
    if n == 0 {
        return None;
    }
    let start = state.cursor.get() as usize % n;
    state.cursor.set(((start + 1) % n) as u32);
    let epoch = c.upstreams.epoch;
    for pass in PASSES {
        let mut best: Option<(u16, (u32, u16))> = None;
        for i in (start..n).chain(0..start) {
            let weight = c.members.weights[i];
            if weight == 0 || !c.ok(i as u16, pass) {
                continue;
            }
            let load = (local.in_flight(c.members.origins[i], epoch), weight);
            if best.is_none_or(|(_, b)| lighter(load, b)) {
                best = Some((i as u16, load));
            }
        }
        if let Some((i, _)) = best {
            return Some(i);
        }
    }
    None
}

/// Maglev lookup and its probes; only the first pass (healthy, untried), so a request whose
/// key lands on a bad member falls back to round robin rather than to another key's origin
/// chosen at random.
#[inline]
fn hashed(c: &Candidates<'_>, table: &[u16], hash: u64) -> Option<u16> {
    let size = table.len() as u64;
    if size == 0 {
        return None;
    }
    let h = mix(hash);
    for i in 0..8u64 {
        let probe = h.wrapping_add(i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let slot = ((u128::from(probe) * u128::from(size)) >> 64) as usize;
        let member = table[slot];
        if c.ok(member, PASSES[0]) {
            return Some(member);
        }
    }
    None
}

/// Entry points for `benches/balance.rs`; not part of the API.
#[cfg(feature = "internals")]
pub mod bench {
    use super::*;
    use crate::exchange::{ConnInfo, Proto, Scheme};
    use crate::plan::{ListenerKey, ListenerKind, Plan, PoolId, Target};
    use crate::upstream::Registry;
    use std::sync::Arc;

    /// One pool of `members` origins under one policy, with the state a core keeps for it.
    pub struct Fixture {
        plan: Plan,
        upstreams: Arc<Upstreams>,
        pools: Pools,
        state: PoolLocal,
        ex: Exchange,
        tried: Tried,
    }

    /// `balance` is the config's value: `"roundRobin"`, `"p2c"`, `{"hash": "..."}`, ...
    pub fn fixture(balance: serde_json::Value, members: usize) -> Fixture {
        let to: Vec<String> = (0..members)
            .map(|i| format!("http://10.0.{}.{}:8080", i / 250, i % 250 + 1))
            .collect();
        let config = serde_json::json!({
            "version": 1,
            "listen": { "http": ["127.0.0.1:1"] },
            "sites": [{ "name": "a", "hosts": ["*"], "routes": [
                { "proxy": { "to": to, "balance": balance } },
            ] }],
        });
        let config =
            crate::config::parse_config(crate::config::Format::Json, config.to_string().as_bytes())
                .expect("bench config")
                .value;
        let (plan, _) =
            crate::plan::compile::compile(&config, &crate::plan::compile::FileSystem, 1)
                .expect("bench plan");
        let upstreams = Registry::new(1).build(&plan);
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
        let mut ex = Exchange::new(conn, plan.var_count);
        ex.req
            .set_line(b"GET", b"/", crate::msg::Version::Http11)
            .unwrap();
        ex.req.push_field(b"Host", b"app.example.com");
        ex.req
            .push_field(b"X-Session", b"3f1c9a7e-5b2d-4e8f-9a6c-0d1e2f3a4b5c");
        Fixture {
            plan,
            upstreams,
            pools: Pools::default(),
            state: PoolLocal::seeded(7),
            ex,
            tried: Tried::new(),
        }
    }

    impl Fixture {
        /// One pick, as `proxy::balanced` makes it for a first attempt.
        #[inline]
        pub fn pick(&mut self) -> u16 {
            let pool = match self.plan.sites[0].routes.steps[0].action {
                crate::plan::Action::Answer(crate::plan::Terminal::Proxy(ref p), _) => p.to,
                _ => unreachable!("the fixture's one step proxies"),
            };
            let Target::Pool(PoolId(id)) = pool else {
                unreachable!("a list of origins is a pool")
            };
            let picked = pick(
                &self.plan.pools[usize::from(id)],
                self.upstreams.members(PoolId(id)),
                &self.upstreams,
                &self.pools,
                &self.state,
                &mut self.ex,
                &self.tried,
                0,
            );
            self.ex.arena.clear();
            picked.map_or(u16::MAX, |o| o.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{ConnInfo, Proto, Scheme};
    use crate::plan::{ListenerKey, ListenerKind, Plan, PoolId, Target};
    use crate::proxy::pool::Busy;
    use crate::runtime::testing::plan_from;
    use crate::upstream::Registry;
    use std::sync::Arc;

    struct Pool {
        plan: Plan,
        up: Arc<Upstreams>,
        id: PoolId,
        pools: Pools,
        state: PoolLocal,
        ex: Exchange,
    }

    fn pool(to: serde_json::Value, balance: serde_json::Value) -> Pool {
        pool_with(serde_json::json!({ "to": to, "balance": balance }))
    }

    fn pool_with(proxy: serde_json::Value) -> Pool {
        let plan = plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": ["127.0.0.1:1"] },
                "sites": [{ "name": "a", "hosts": ["*"], "routes": [{ "proxy": proxy }] }],
            }),
        );
        let up = Registry::new(1).build(&plan);
        let crate::plan::Action::Answer(crate::plan::Terminal::Proxy(p), _) =
            &plan.sites[0].routes.steps[0].action
        else {
            unreachable!()
        };
        let Target::Pool(id) = p.to else {
            panic!("{:?}", p.to)
        };
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
        let mut ex = Exchange::new(conn, plan.var_count);
        ex.req
            .set_line(b"GET", b"/", crate::msg::Version::Http11)
            .unwrap();
        Pool {
            plan,
            up,
            id,
            pools: Pools::default(),
            state: PoolLocal::seeded(1),
            ex,
        }
    }

    fn urls(n: usize) -> serde_json::Value {
        (0..n)
            .map(|i| format!("http://10.0.0.{}:80", i + 1))
            .collect::<Vec<_>>()
            .into()
    }

    impl Pool {
        fn pick_with(&mut self, tried: &Tried, now: u32) -> Option<OriginId> {
            let picked = pick(
                &self.plan.pools[usize::from(self.id.0)],
                self.up.members(self.id),
                &self.up,
                &self.pools,
                &self.state,
                &mut self.ex,
                tried,
                now,
            );
            self.ex.arena.clear();
            picked
        }
        fn pick(&mut self) -> Option<OriginId> {
            self.pick_with(&Tried::new(), 0)
        }
        /// Picks per origin over `n` picks.
        fn counts(&mut self, n: usize) -> Vec<usize> {
            let mut counts = vec![0; self.up.origins().len()];
            for _ in 0..n {
                counts[usize::from(self.pick().unwrap().0)] += 1;
            }
            counts
        }
        fn busy(&self, origin: u16, requests: usize) -> Vec<Busy> {
            (0..requests)
                .map(|_| self.pools.busy(OriginId(origin), self.up.epoch).unwrap())
                .collect()
        }
        fn health(&self, origin: u16) -> &crate::upstream::Health {
            &self.up.origin(OriginId(origin)).health
        }
    }

    fn within(count: usize, total: usize, share: f64, tolerance: f64) -> bool {
        (count as f64 / total as f64 - share).abs() <= tolerance
    }

    #[test]
    fn round_robin_and_weights_split_100k_picks_within_one_percent() {
        let mut p = pool(urls(4), "roundRobin".into());
        let counts = p.counts(100_000);
        assert!(
            counts.iter().all(|&c| within(c, 100_000, 0.25, 0.01)),
            "{counts:?}"
        );

        let mut p = pool(
            serde_json::json!([
                { "url": "http://10.0.0.1:80", "weight": 5 },
                { "url": "http://10.0.0.2:80", "weight": 3 },
                "http://10.0.0.3:80",
                { "url": "http://10.0.0.4:80", "weight": 0 },
            ]),
            "roundRobin".into(),
        );
        let counts = p.counts(100_000);
        for (i, share) in [5.0 / 9.0, 3.0 / 9.0, 1.0 / 9.0, 0.0]
            .into_iter()
            .enumerate()
        {
            assert!(within(counts[i], 100_000, share, 0.01), "{counts:?}");
        }
        assert_eq!(counts[3], 0, "weight 0 drains");
    }

    #[test]
    fn p2c_follows_weights_and_avoids_the_loaded_member() {
        let mut p = pool(urls(4), "p2c".into());
        let counts = p.counts(100_000);
        assert!(
            counts.iter().all(|&c| within(c, 100_000, 0.25, 0.01)),
            "{counts:?}"
        );
        let _held = p.busy(0, 10);
        let counts = p.counts(100_000);
        assert!(
            within(counts[0], 100_000, 0.0, 0.0),
            "two distinct draws: the loaded member always meets a lighter one: {counts:?}"
        );
        assert!(
            counts[1..]
                .iter()
                .all(|&c| within(c, 100_000, 1.0 / 3.0, 0.01)),
            "{counts:?}"
        );

        let mut p = pool(
            serde_json::json!([
                { "url": "http://10.0.0.1:80", "weight": 3 },
                "http://10.0.0.2:80",
            ]),
            "p2c".into(),
        );
        let _held = (p.busy(0, 2), p.busy(1, 1));
        let counts = p.counts(10_000);
        assert_eq!(
            counts,
            [10_000, 0],
            "2 in flight at weight 3 is lighter than 1 at weight 1"
        );
    }

    #[test]
    fn least_requests_picks_the_lightest_and_rotates_ties() {
        let mut p = pool(urls(3), "leastRequests".into());
        let counts = p.counts(90_000);
        assert_eq!(counts, [30_000; 3], "ties rotate");
        let _held = (p.busy(0, 3), p.busy(1, 1), p.busy(2, 2));
        assert_eq!(p.counts(1000), [0, 1000, 0]);

        let mut p = pool(
            serde_json::json!([
                { "url": "http://10.0.0.1:80", "weight": 4 },
                "http://10.0.0.2:80",
            ]),
            "leastRequests".into(),
        );
        let _held = (p.busy(0, 3), p.busy(1, 1));
        assert_eq!(p.counts(100), [100, 0], "3/4 is lighter than 1/1");
    }

    #[test]
    fn hash_sends_one_key_to_one_origin_and_moves_it_only_when_that_origin_is_out() {
        let mut p = pool(urls(5), serde_json::json!({ "hash": "{header.x-user}" }));
        let mut owner = Vec::new();
        for user in 0..1000 {
            p.ex.req.fields.clear();
            p.ex.req
                .push_field(b"X-User", format!("u{user}").as_bytes());
            let first = p.pick().unwrap();
            assert!((0..10).all(|_| p.pick() == Some(first)));
            owner.push(first);
        }
        let mut per = [0usize; 5];
        for o in &owner {
            per[usize::from(o.0)] += 1;
        }
        assert!(per.iter().all(|&c| within(c, 1000, 0.2, 0.05)), "{per:?}");

        p.health(2).set_probe(true);
        for (user, &was) in owner.iter().enumerate() {
            p.ex.req.fields.clear();
            p.ex.req
                .push_field(b"X-User", format!("u{user}").as_bytes());
            let now = p.pick().unwrap();
            if was == OriginId(2) {
                assert_ne!(now, was);
            } else {
                assert_eq!(now, was, "keys of healthy origins stay");
            }
        }

        p.ex.req.fields.clear();
        let counts = p.counts(5000);
        assert_eq!(counts[2], 0);
        assert!(
            counts.iter().filter(|&&c| c > 0).all(|&c| c == 1250),
            "no key: round robin over the healthy ones: {counts:?}"
        );
    }

    #[test]
    fn a_retry_prefers_an_untried_origin_and_reuses_one_when_none_is_left() {
        let mut p = pool(urls(2), "roundRobin".into());
        let first = p.pick().unwrap();
        let tried: Tried = [first].into_iter().collect();
        for _ in 0..10 {
            assert_ne!(p.pick_with(&tried, 0), Some(first));
        }
        let both: Tried = [OriginId(0), OriginId(1)].into_iter().collect();
        assert!(
            p.pick_with(&both, 0).is_some(),
            "reuse when every one was tried"
        );

        let mut one = pool_with(serde_json::json!({ "to": urls(1), "retries": 1 }));
        let only: Tried = [OriginId(0)].into_iter().collect();
        assert_eq!(one.pick_with(&only, 0), Some(OriginId(0)));
    }

    #[test]
    fn probe_down_members_are_never_picked_and_ejected_ones_only_when_all_are() {
        let mut p = pool(urls(3), "roundRobin".into());
        p.health(0).set_probe(true);
        assert_eq!(p.counts(300), [0, 150, 150]);

        let local = crate::proxy::pool::OriginLocal::default();
        let passive = crate::plan::PassivePlan {
            max_fails: 1,
            cooldown: 10,
        };
        let eject = |p: &Pool, i: u16| {
            crate::upstream::health::observe(
                p.up.origin(OriginId(i)),
                &local,
                Some(&passive),
                crate::upstream::health::Outcome::Failed,
                0,
            )
        };
        eject(&p, 1);
        assert_eq!(p.counts(10), [0, 0, 10]);
        eject(&p, 2);
        assert_eq!(
            p.counts(10),
            [0, 5, 5],
            "every member whose probe is up is ejected: all of those come back"
        );
        p.health(1).set_probe(true);
        p.health(2).set_probe(true);
        assert_eq!(p.pick(), None, "every probe down: nothing to pick");
    }
}
