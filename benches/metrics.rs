//! Counting a request into `metrics::Counters`, and rendering a scrape.

use criterion::{Criterion, criterion_group, criterion_main};

fn metrics(c: &mut Criterion) {
    let _ = c;
}

criterion_group!(benches, metrics);
criterion_main!(benches);
