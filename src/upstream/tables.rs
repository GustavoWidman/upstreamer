//! Per-policy member tables, built off the request path.

use super::maglev;
use crate::plan::BalancePlan;
use crate::upstream::Select;

/// The longest weighted sequence. Larger weight sums are scaled down to fit (every member
/// with a weight keeps at least one entry).
const MAX_SEQUENCE: u64 = 4096;

/// The table a pool's policy reads, from its members' identity hashes and weights: the
/// weighted sequence (round robin, p2c's weighted draw), Maglev plus the sequence (hash), or
/// nothing (least requests reads the weights as they are). Deterministic: equal inputs give
/// equal tables, on every replica.
pub(super) fn select(balance: &BalancePlan, member_keys: &[u64], weights: &[u16]) -> Select {
    match balance {
        BalancePlan::RoundRobin | BalancePlan::P2c => Select::Sequence(sequence(weights)),
        BalancePlan::LeastRequests => Select::Weights,
        BalancePlan::Hash(_) => Select::Maglev {
            table: maglev::build(member_keys, weights, maglev::size(member_keys.len())),
            fallback: sequence(weights),
        },
    }
}

/// Smooth weighted round robin (nginx's), unrolled over one period: each member appears
/// `weight` times, spread out rather than in runs, so a cursor walking it alternates members
/// even at uneven weights. Weights are divided by their common divisor first, then scaled
/// down when the period would pass [`MAX_SEQUENCE`] entries. Weight-0 members never appear.
pub(super) fn sequence(weights: &[u16]) -> Box<[u16]> {
    let divisor = weights
        .iter()
        .filter(|&&w| w > 0)
        .fold(0u64, |g, &w| gcd(g, u64::from(w)));
    if divisor == 0 {
        return Box::new([]);
    }
    let mut scaled: Vec<u64> = weights.iter().map(|&w| u64::from(w) / divisor).collect();
    let total: u64 = scaled.iter().sum();
    if total > MAX_SEQUENCE {
        for w in scaled.iter_mut().filter(|w| **w > 0) {
            *w = (*w * MAX_SEQUENCE / total).max(1);
        }
    }
    let total: i64 = scaled.iter().sum::<u64>() as i64;
    let mut current = vec![0i64; scaled.len()];
    let mut out = Vec::with_capacity(total as usize);
    for _ in 0..total {
        let mut best = usize::MAX;
        for (i, &w) in scaled.iter().enumerate() {
            if w == 0 {
                continue;
            }
            current[i] += w as i64;
            if best == usize::MAX || current[i] > current[best] {
                best = i;
            }
        }
        current[best] -= total;
        out.push(best as u16);
    }
    out.into()
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_weights_are_one_entry_each_in_member_order() {
        assert_eq!(&*sequence(&[1, 1, 1]), [0, 1, 2]);
        assert_eq!(&*sequence(&[7, 7]), [0, 1], "a common divisor is taken out");
    }

    #[test]
    fn uneven_weights_interleave() {
        assert_eq!(&*sequence(&[5, 1, 1]), [0, 0, 1, 0, 2, 0, 0]);
        assert_eq!(
            &*sequence(&[2, 0, 1]),
            [0, 2, 0],
            "a drained member never appears"
        );
    }

    #[test]
    fn long_periods_are_scaled_down_keeping_every_member() {
        let seq = sequence(&[1000, 999, 1]);
        assert!(seq.len() as u64 <= MAX_SEQUENCE + 2, "{}", seq.len());
        assert_eq!(seq.iter().filter(|&&i| i == 2).count(), 1);
        let first = seq.iter().filter(|&&i| i == 0).count() as f64;
        assert!((first / seq.len() as f64 - 1000.0 / 2000.0).abs() < 0.01);
    }

    #[test]
    fn nothing_to_pick_is_an_empty_sequence() {
        assert!(sequence(&[]).is_empty());
        assert!(sequence(&[0, 0]).is_empty());
    }
}
