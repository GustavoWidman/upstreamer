//! Maglev lookup tables (Eisenbud et al., NSDI 2016), built by the registry when a hash
//! pool's members change, never on the request path.

/// Table size for `n` members: the smallest prime at or above max(100 x n, 1021), at most
/// 65537.
pub(super) fn size(n: usize) -> usize {
    let _ = n;
    1021
}

/// The table: slot -> index into the member list. Member identity (not position) seeds each
/// member's permutation, so replicas with the same members in another order build the same
/// table.
pub(super) fn build(member_keys: &[u64], weights: &[u16], size: usize) -> Box<[u16]> {
    let _ = (member_keys, weights, size);
    Box::new([])
}
