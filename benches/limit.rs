//! `limit::Limiters::admit`, uncontended and contended.

use criterion::{Criterion, criterion_group, criterion_main};

fn limit(c: &mut Criterion) {
    let _ = c;
}

criterion_group!(benches, limit);
criterion_main!(benches);
