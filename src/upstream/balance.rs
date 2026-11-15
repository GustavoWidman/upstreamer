//! Choosing an origin for one attempt. Reads the pool's policy (plan), its members and tables
//! (`Upstreams`), each candidate's `Health`, and this core's counters; writes only this core's
//! cursor and random state.

use crate::exchange::Exchange;
use crate::plan::{OriginId, PoolPlan};
use crate::proxy::pool::Pools;
use crate::upstream::{Members, Upstreams};
use smallvec::SmallVec;
use std::cell::Cell;

/// Origins earlier attempts of this request used.
pub(crate) type Tried = SmallVec<[OriginId; 4]>;

/// Per-core state of one pool, indexed by `PoolId` of the core's current plan.
#[derive(Default)]
pub(crate) struct PoolLocal {
    /// Position in the pool's sequence.
    pub cursor: Cell<u32>,
    /// Random state for p2c.
    pub rng: Cell<u64>,
}

/// The origin for the next attempt, or `None` when no member may be picked.
pub(crate) fn pick(
    pool: &PoolPlan,
    members: &Members,
    upstreams: &Upstreams,
    local: &Pools,
    ex: &mut Exchange,
    tried: &Tried,
    now: u32,
) -> Option<OriginId> {
    let _ = (pool, members, upstreams, local, ex, tried, now);
    None
}

/// Entry points for `benches/balance.rs`; not part of the API.
#[cfg(feature = "internals")]
pub mod bench {}
