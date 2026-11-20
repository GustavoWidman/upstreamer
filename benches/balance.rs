//! `upstream::balance::pick` per policy and member count, every member healthy, as a first
//! attempt makes it. Budgets: round robin and p2c at 16 members 15 ns or less, hash on a
//! header key 40 ns or less.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;
use std::hint::black_box;
use upstreamer::bench::balance::fixture;

fn balance(c: &mut Criterion) {
    let mut group = c.benchmark_group("pick");
    let policies = [
        ("round_robin", json!("roundRobin")),
        ("p2c", json!("p2c")),
        ("least_requests", json!("leastRequests")),
        ("hash_header", json!({ "hash": "{header.x-session}" })),
        ("hash_remote_host", json!({ "hash": "{remote_host}" })),
    ];
    for (name, policy) in policies {
        for members in [2, 16, 64] {
            let mut f = fixture(policy.clone(), members);
            group.bench_with_input(BenchmarkId::new(name, members), &members, |b, _| {
                b.iter(|| black_box(f.pick()))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, balance);
criterion_main!(benches);
