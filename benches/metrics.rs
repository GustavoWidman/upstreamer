//! Counting a request into `metrics::Counters`, and rendering a scrape.
//!
//! `count` is what `observe::finish` adds for a proxied request (budget: a few ns). `scrape`
//! renders the exposition of two cores' published counts (budget: 1 ms for 1000 series on
//! one core).

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use upstreamer::bench::metrics::{Requests, Scrape};

fn metrics(c: &mut Criterion) {
    let requests = Requests::new();
    c.bench_function("metrics/count", |b| {
        b.iter(|| requests.count(black_box(Duration::from_micros(1_700))))
    });

    let mut group = c.benchmark_group("metrics/scrape");
    // About 1000 and 10000 series: each route has four status classes and a histogram, and
    // its own origin with responses, five failure causes, a histogram, health and in-flight.
    for routes in [23, 230] {
        let mut scrape = Scrape::new(routes, 2);
        scrape.render();
        let series = scrape.samples();
        group.throughput(Throughput::Elements(series as u64));
        group.bench_with_input(BenchmarkId::from_parameter(series), &routes, |b, _| {
            b.iter(|| black_box(scrape.render()))
        });
    }
    group.finish();
}

criterion_group!(benches, metrics);
criterion_main!(benches);
