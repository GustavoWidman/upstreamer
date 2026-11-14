//! HTTP/1.1 codec throughput on the fleet's hot path: a request as Cloudflare forwards it to an
//! origin, and a typical upstream response. Before measuring, a counting allocator checks
//! that warm parses and serialisations allocate nothing.

use criterion::{Criterion, Throughput, criterion_group};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use upstreamer::codec::{Requests, Responses};

/// Counts allocations made by the current thread.
struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

/// A browser GET as Cloudflare sends it to an origin over HTTP/1.1: its own headers
/// (CF-Ray, CF-Connecting-IP, CF-IPCountry, CF-Visitor, X-Forwarded-*, CDN-Loop) plus the
/// browser's.
const CLOUDFLARE_REQUEST: &[u8] = b"GET /blog/thread-per-core-proxies?ref=home HTTP/1.1\r\n\
Host: r3dlust.com\r\n\
Connection: Keep-Alive\r\n\
Accept-Encoding: gzip, br\r\n\
CF-Ray: 8f1b2c3d4e5f6a7b-GRU\r\n\
X-Forwarded-For: 203.0.113.7\r\n\
CF-Visitor: {\"scheme\":\"https\"}\r\n\
X-Forwarded-Proto: https\r\n\
CF-Connecting-IP: 203.0.113.7\r\n\
CF-IPCountry: BR\r\n\
CDN-Loop: cloudflare; loops=1\r\n\
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0\r\n\
accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
accept-language: en-US,en;q=0.9,pt-BR;q=0.8\r\n\
cookie: theme=dark; _ga=GA1.1.123456789.1700000000; session=f3a9c1e0b7d24c6e9a1f\r\n\
referer: https://r3dlust.com/\r\n\
upgrade-insecure-requests: 1\r\n\
sec-fetch-dest: document\r\n\
sec-fetch-mode: navigate\r\n\
sec-fetch-site: same-origin\r\n\
sec-fetch-user: ?1\r\n\
priority: u=0, i\r\n\
\r\n";

const UPSTREAM_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: 18342\r\n\
Cache-Control: public, max-age=0, must-revalidate\r\n\
ETag: \"1b2c3d4e5f6a7b8c9d0e1f2a3b\"\r\n\
Vary: Accept-Encoding\r\n\
X-Content-Type-Options: nosniff\r\n\
Date: Sat, 14 Nov 2026 12:00:00 GMT\r\n\
Keep-Alive: timeout=5\r\n\
Connection: keep-alive\r\n\
\r\n";

const DATE: &[u8] = b"Sat, 14 Nov 2026 12:00:01 GMT";

fn assert_no_allocation_after_warm_up() {
    let mut requests = Requests::default();
    let mut responses = Responses::default();
    let cold = allocations();
    assert!(requests.forward(CLOUDFLARE_REQUEST) > 0);
    assert!(responses.relay(UPSTREAM_RESPONSE, DATE) > 0);
    let warm_up = allocations() - cold;
    println!("allocations while the first round sizes the buffers: {warm_up}");
    assert!(warm_up > 0, "the counter sees allocations");
    let before = allocations();
    for _ in 0..1000 {
        black_box(requests.parse(black_box(CLOUDFLARE_REQUEST)));
        black_box(requests.forward(black_box(CLOUDFLARE_REQUEST)));
        black_box(responses.relay(black_box(UPSTREAM_RESPONSE), DATE));
    }
    let made = allocations() - before;
    println!("allocations in 1000 warm parse/forward/relay rounds: {made}");
    assert_eq!(made, 0, "warm codec paths allocate");
}

fn codec(c: &mut Criterion) {
    let mut g = c.benchmark_group("h1");
    g.throughput(Throughput::Elements(1));
    let mut requests = Requests::default();
    g.bench_function("parse_cloudflare_request", |b| {
        b.iter(|| requests.parse(black_box(CLOUDFLARE_REQUEST)))
    });
    g.bench_function("parse_and_forward_cloudflare_request", |b| {
        b.iter(|| requests.forward(black_box(CLOUDFLARE_REQUEST)))
    });
    let mut responses = Responses::default();
    g.bench_function("parse_and_relay_response", |b| {
        b.iter(|| responses.relay(black_box(UPSTREAM_RESPONSE), DATE))
    });
    g.finish();
}

criterion_group!(benches, codec);

fn main() {
    assert_no_allocation_after_warm_up();
    benches();
    Criterion::default().configure_from_args().final_summary();
}
