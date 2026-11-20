//! Maglev lookup tables (Eisenbud et al., NSDI 2016), built by the registry when a hash
//! pool's members change, never on the request path.
//!
//! Each member walks its own permutation of the table's slots (an offset and a skip derived
//! from its identity) and claims the next free slot of it in turn. A member with a larger
//! weight takes turns proportionally more often (the weighted variant Envoy uses). Removing
//! one member frees only its slots, which the others claim along their own permutations, so
//! keys owned by the remaining members mostly stay; adding one takes about 1/n of the slots.

/// The largest table: a prime above 2^16, so indices still fit the slots of 65536 members.
const MAX_SIZE: usize = 65537;
/// The smallest table: about 1% balance for up to 20 members.
const MIN_SIZE: usize = 2048;

/// Table size for `n` members: the smallest prime at or above 100 x n rounded up to a power
/// of two (at least 2048), at most 65537. The size is part of every key's slot, so it only
/// changes when the member count crosses a power-of-two band: adding or removing a member
/// inside a band moves only the keys Maglev must move.
pub(super) fn size(n: usize) -> usize {
    let mut candidate = n
        .saturating_mul(100)
        .max(MIN_SIZE)
        .checked_next_power_of_two()
        .unwrap_or(MAX_SIZE)
        .min(MAX_SIZE);
    while !is_prime(candidate) {
        candidate += 1;
    }
    candidate
}

fn is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    let mut d = 2;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 1;
    }
    true
}

/// The table: slot -> index into the member list. Member identity (not position) seeds each
/// member's permutation and orders the turns, so replicas with the same members in another
/// order build the same table, slot for slot, up to the index renaming. Members of weight 0
/// own no slot; with no member of weight above 0 the table is empty.
pub(super) fn build(member_keys: &[u64], weights: &[u16], size: usize) -> Box<[u16]> {
    debug_assert_eq!(member_keys.len(), weights.len());
    let mut order: Vec<usize> = (0..member_keys.len()).filter(|&i| weights[i] > 0).collect();
    if order.is_empty() || size == 0 {
        return Box::new([]);
    }
    order.sort_by_key(|&i| (member_keys[i], i));
    let max_weight = order
        .iter()
        .map(|&i| u64::from(weights[i]))
        .max()
        .unwrap_or(1);
    let modulus = size as u64;
    let walks: Vec<(u64, u64)> = order
        .iter()
        .map(|&i| {
            let key = member_keys[i];
            let offset = mix(key ^ 0x9e37_79b9_7f4a_7c15) % modulus;
            let skip = mix(key ^ 0xc2b2_ae3d_27d4_eb4f) % (modulus - 1) + 1;
            (offset, skip)
        })
        .collect();
    let mut next = vec![0u64; order.len()];
    let mut placed = vec![0u64; order.len()];
    let mut table = vec![u16::MAX; size];
    let mut filled = 0usize;
    let mut round = 0u64;
    while filled < size {
        round += 1;
        for (k, &member) in order.iter().enumerate() {
            // A member takes a turn while its share of the slots, round * w / max_w, is ahead
            // of what it holds: equal weights alternate, as in the paper.
            if placed[k] * max_weight >= round * u64::from(weights[member]) {
                continue;
            }
            let (offset, skip) = walks[k];
            loop {
                let slot = ((offset + next[k] * skip) % modulus) as usize;
                next[k] += 1;
                if table[slot] == u16::MAX {
                    table[slot] = member as u16;
                    placed[k] += 1;
                    filled += 1;
                    break;
                }
            }
            if filled == size {
                break;
            }
        }
    }
    table.into()
}

/// The 64-bit finaliser of MurmurHash3: spreads every input bit over every output bit, so
/// identity hashes that differ in a few low bits get unrelated walks and keys unrelated slots.
#[inline]
pub(crate) fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u64) -> Vec<u64> {
        (0..n).map(|i| mix(i + 1000)).collect()
    }

    /// The member each of 100k request keys lands on, by member key.
    fn owners(member_keys: &[u64], weights: &[u16]) -> Vec<u64> {
        let table = build(member_keys, weights, size(member_keys.len()));
        (0..100_000u64)
            .map(|k| {
                let slot = (mix(k) % table.len() as u64) as usize;
                member_keys[table[slot] as usize]
            })
            .collect()
    }

    fn moved(a: &[u64], b: &[u64]) -> f64 {
        a.iter().zip(b).filter(|(x, y)| x != y).count() as f64 / a.len() as f64
    }

    #[test]
    fn sizes_are_primes_of_at_least_a_hundred_slots_per_member_in_power_of_two_bands() {
        assert_eq!(size(1), 2053);
        assert_eq!(size(20), 2053);
        assert_eq!(size(21), 4099);
        assert_eq!(size(100), 16411);
        assert_eq!(size(1000), 65537, "capped");
    }

    #[test]
    fn every_slot_is_owned_and_members_share_by_weight() {
        let members = keys(4);
        let table = build(&members, &[1, 1, 2, 0], 1021);
        assert_eq!(table.len(), 1021);
        let count = |m: u16| table.iter().filter(|&&s| s == m).count() as f64 / 1021.0;
        assert!(
            table.iter().all(|&s| s < 3),
            "a drained member owns no slot"
        );
        for (m, share) in [(0, 0.25), (1, 0.25), (2, 0.5)] {
            assert!(
                (count(m) - share).abs() < 0.01,
                "member {m}: {} of the slots",
                count(m)
            );
        }
    }

    #[test]
    fn removing_one_of_ten_members_moves_little_more_than_its_keys() {
        let all = keys(10);
        let before = owners(&all, &[1; 10]);
        let after = owners(&all[..9], &[1; 9]);
        let share = moved(&before, &after);
        assert!(share <= 0.12, "{share} of the keys moved");
        assert!(share >= 0.09, "the removed member's keys moved: {share}");
    }

    #[test]
    fn adding_an_eleventh_member_moves_about_one_eleventh_of_the_keys() {
        let all = keys(11);
        let before = owners(&all[..10], &[1; 10]);
        let after = owners(&all, &[1; 11]);
        let share = moved(&before, &after);
        assert!(
            (share - 1.0 / 11.0).abs() < 0.03,
            "{share} of the keys moved"
        );
    }

    #[test]
    fn permuted_members_build_the_same_table() {
        let members = keys(7);
        let weights = [1, 2, 1, 3, 1, 1, 5];
        let mut order: Vec<usize> = (0..7).collect();
        order.reverse();
        order.swap(1, 4);
        let permuted: Vec<u64> = order.iter().map(|&i| members[i]).collect();
        let permuted_weights: Vec<u16> = order.iter().map(|&i| weights[i]).collect();
        let a = build(&members, &weights, 1021);
        let b = build(&permuted, &permuted_weights, 1021);
        let by_identity = |table: &[u16], keys: &[u64]| -> Vec<u64> {
            table.iter().map(|&s| keys[s as usize]).collect()
        };
        assert_eq!(by_identity(&a, &members), by_identity(&b, &permuted));
    }

    #[test]
    fn no_member_with_weight_gives_an_empty_table() {
        assert!(build(&keys(2), &[0, 0], 1021).is_empty());
        assert!(build(&[], &[], 1021).is_empty());
    }
}
