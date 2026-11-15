//! `upstream::balance::pick` per policy and member count.

use criterion::{Criterion, criterion_group, criterion_main};

fn balance(c: &mut Criterion) {
    let _ = c;
}

criterion_group!(benches, balance);
criterion_main!(benches);
