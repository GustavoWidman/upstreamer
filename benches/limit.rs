//! `limit::Limiters::admit`, uncontended and with four cores on one bucket. Every request is
//! admitted, which is the path that writes: a refusal only reads.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Barrier;
use std::time::{Duration, Instant};
use upstreamer::bench::limit::{Fixture, Key};

const CLIENTS: u32 = 4096;
const THREADS: usize = 4;

fn limit(c: &mut Criterion) {
    let mut group = c.benchmark_group("admit");

    let per_client = Fixture::new(Key::PerClient);
    let mut lane = per_client.lane();
    group.bench_function("one client", |b| {
        b.iter(|| assert!(lane.admit(black_box(0x0a00_0001))))
    });
    let mut client = 0u32;
    group.bench_function("4096 clients", |b| {
        b.iter(|| {
            client = (client + 1) % CLIENTS;
            assert!(lane.admit(black_box(0x0a00_0000 + client)))
        })
    });

    let constant = Fixture::new(Key::Constant);
    let mut lane = constant.lane();
    group.bench_function("constant key, one thread", |b| {
        b.iter(|| assert!(lane.admit(black_box(0x0a00_0001))))
    });

    group.bench_function("constant key, 4 threads", |b| {
        b.iter_custom(|iters| {
            let barrier = Barrier::new(THREADS);
            std::thread::scope(|scope| {
                let handles: Vec<_> = (0..THREADS)
                    .map(|n| {
                        let mut lane = constant.lane();
                        let barrier = &barrier;
                        scope.spawn(move || {
                            barrier.wait();
                            let start = Instant::now();
                            for _ in 0..iters {
                                assert!(lane.admit(black_box(0x0a00_0000 + n as u32)));
                            }
                            start.elapsed()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .max()
                    .unwrap_or(Duration::ZERO)
            })
        })
    });
    group.finish();
}

criterion_group!(benches, limit);
criterion_main!(benches);
