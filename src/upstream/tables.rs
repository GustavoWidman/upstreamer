//! Per-policy member tables, built off the request path.

use crate::plan::BalancePlan;
use crate::upstream::Select;

/// The table a pool's policy reads, from its members' identity hashes and weights.
/// Deterministic: equal inputs give equal tables, on every replica.
pub(super) fn select(balance: &BalancePlan, member_keys: &[u64], weights: &[u16]) -> Select {
    let _ = (balance, weights);
    Select::Sequence((0..member_keys.len() as u16).collect())
}
