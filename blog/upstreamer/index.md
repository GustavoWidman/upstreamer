# Building a reverse proxy in Rust

I got an hour to build a reverse proxy in a technical interview. It worked — barely. One `match` statement, no graceful error handling, no tests, no config reload. After the interview I kept thinking about what a proper version would look like. This is that version.

The project is called [upstreamer](https://github.com/GustavoWidman/upstreamer). It's a reverse proxy written in Rust, designed around Kubernetes service discovery and zero-downtime config reload. Not a toy — something you could actually run.

## What it does

- Routes requests by host (glob) and path (prefix)
- Three load balancing algorithms: round-robin, weighted-latency (EWMA), weighted-metrics
- Per-IP token bucket rate limiting
- Kubernetes upstream discovery via Service watches
- Hot config reload without dropping connections
- Prometheus metrics on a separate port
- Active and passive health checking
- Custom error pages

No TLS, no WebSocket, no streaming bodies — those are deliberate v1 omissions.

## Architecture

```
Client → TcpListener → spawn per-connection
  → parse request → match route → check rate limit
  → select origin (LB) → proxy to origin → record latency/metrics
  → respond to client
```

The core loop is straightforward. The interesting parts are how state is shared and how config changes propagate without stopping the world.

### Shared state with ArcSwap

`AppState` holds the config and router behind `arc_swap::ArcSwap`. This gives us lock-free reads — the hot path never blocks waiting for a config update. When config changes, we build a new `Router`, validate it, and atomically swap the pointer. In-flight requests keep using the old router until they finish. No mutex, no RCU complexity, just an atomic pointer swap.

Origin state (EWMA latencies, failure counts, health status) lives in a `DashMap`, keyed by origin URL. Each origin gets its own `OriginState` with `AtomicU64` for latency and `AtomicBool` for health. The load balancer reads these with `Ordering::Relaxed` — we don't need strict consistency for latency estimation, just trend detection.

### Load balancing

The trait is simple:

```rust
#[async_trait]
pub trait LoadBalancer: Send + Sync {
    async fn select_origin(&self, candidates: &[String], states: &DashMap<String, OriginState>) -> Option<String>;
}
```

**Round-robin** uses an `AtomicU64` counter, skipping unhealthy origins. Two lines of logic, hard to get wrong.

**Weighted-latency** tracks EWMA latency per origin with α = 0.1:

```
new_latency = 0.1 × sample + 0.9 × old_latency
```

Weight is `1 / (latency_ns + 1)`. The `+ 1` avoids division by zero and gives low-latency origins proportionally more traffic. Selection is weighted random — build a cumulative distribution, pick a random point, find the bucket. Not as precise as least-connections for variable request sizes, but latency-weighted random is simpler and works well when request sizes are roughly uniform.

The EWMA update uses a CAS loop to avoid locking:

```rust
loop {
    let old = self.ewma_latency_ns.load(Ordering::Relaxed);
    let new = (alpha * sample_ns as f64 + (1.0 - alpha) * old as f64) as u64;
    if self.ewma_latency_ns.compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        break;
    }
}
```

CAS contention is low in practice — the loop rarely retries because updates are once-per-request per origin and the window between load and store is tiny.

**Weighted-metrics** was meant to factor in Kubernetes pod pressure (from metrics-server). The plumbing is there but metrics-server integration is stubbed for v1, so it falls back to latency-weighted behavior.

### Rate limiting

I built a token bucket from scratch instead of pulling in the `governor` crate. The math is simple: track `tokens` (f64), `max_tokens`, `refill_rate`, and `last_refill` timestamp. On each request:

1. Calculate elapsed time since last refill
2. Add `elapsed × refill_rate` tokens, cap at `max_tokens`
3. If `tokens >= 1.0`, consume one and allow the request

Buckets live in a `DashMap` keyed by IP. Stale buckets (no requests for N seconds) get evicted by a periodic cleanup task. The `check()` method uses the entry API for TOCTOU-free consumption — a single atomic decision per request.

```rust
match self.buckets.entry(ip.to_string()) {
    Entry::Occupied(mut e) => e.get_mut().try_consume(),
    Entry::Vacant(e) => {
        let mut bucket = TokenBucket::new(self.max_tokens, self.refill_rate);
        let ok = bucket.try_consume();
        e.insert(bucket);
        ok
    }
}
```

Is this better than `governor`? No. Governor uses GCRA, which is more precise and handles burst dynamics better. But building it was the point — understanding why GCRA exists requires understanding what token buckets get wrong, and you can't get that from a crate import.

### Kubernetes discovery

Upstreamer watches `v1::Service` objects in a configured namespace with a label selector. Services annotated with `upstreamer.ora.ooo/pool` get mapped to origin URLs using `clusterIP:port`. When the watch stream fires, it rebuilds the router by merging k8s origins into the statically configured pools, then swaps via ArcSwap.

Why Services and not EndpointSlices? EndpointSlices give you individual pod IPs, which is more granular. But for a reverse proxy, the Service abstraction is the right layer — you want traffic to go through the Service's cluster IP so kube-proxy handles pod-level distribution. Using EndpointSlices would mean the proxy itself is doing pod-level load balancing, which duplicates kube-proxy's job. If you're running in a cluster, let the cluster do its thing.

The watch uses `kube_runtime::watcher` with `WatchStreamExt::applied_objects()` to get a stream of current state. No informer caching needed — we just rebuild the router on every event.

### Config hot-reload

The `notify` crate watches the config file with a 500ms debounce. On change:

1. Reload and parse the TOML
2. Validate (routes have pools, pools have origins, URLs are valid)
3. Build new router
4. Clear stale per-route rate limiters
5. Swap config and router via ArcSwap

If validation fails, the old config stays live. Bad config never crashes the proxy.

One v1 limitation: the global rate limiter isn't hot-swappable because `RateLimiter` state (active buckets) would be lost on swap. Per-route limiters are recreated, but the global one keeps its old config until restart. Honest trade-off — fixing it requires migrating bucket state between limiters.

### Body handling

Request and response bodies are fully collected before forwarding. This is a v1 choice, not an architectural limitation. The collection uses `BytesMut` with `extend_from_slice` on each chunk, then `freeze()` — the fix for the original per-chunk `Bytes::from` that was allocating on every data frame. For small API payloads (typical reverse proxy workload), collecting is fast. For large file transfers, streaming would be better, and the hyper API supports it — just needs plumbing.

### Prometheus metrics

Metrics use the `metrics` facade with the Prometheus exporter. Self-metrics are collected every 5 seconds from `/proc/self/statm` (RSS), `/proc/self/fd` (open file descriptors), and `/proc/self/stat` (CPU ticks via `sysconf(_SC_CLK_TCK)`). Per-origin latency is a histogram recording proxy round-trip time in nanoseconds.

Process metrics from `/proc` instead of crates like `tikv-jemalloc` or `process_collector` keeps the dependency tree small. Six lines to read a file, parse a number, set a gauge. No need for a crate.

### Health checks

Two modes, both configurable:

**Active**: a background task probes all origins at a configured interval. Uses a separate lightweight HTTP client (not the proxy's shared client, so health check traffic doesn't compete with proxy traffic). Consecutive successes/failures flip the `healthy` flag.

**Passive**: tracks failures and successes in the proxy hot path. If an origin returns errors above the threshold, it's marked unhealthy. If it recovers (consecutive successes above threshold), it's marked healthy again.

The health server runs on the metrics port, with `/healthz` (JSON status), `/healthz/upstreams` (per-origin detail), and `/metrics` (Prometheus text).

## Profiling

Benchmark setup: upstreamer proxying to a Python `http.server` backend, both on localhost, with `oha` generating load.

Cold start RSS is ~8.5 MB. After the connection pool warms up and metrics state is allocated, it settles around 14.8 MB. Through three rounds of 50,000 requests each (150k total), RSS held at 14.8 MB with no growth.

```
Round 1: 8.7 → 14.4 MB (warm-up)
Round 2: 14.4 → 14.7 MB
Round 3: 14.7 → 14.8 MB
```

With a warm connection pool, throughput was ~115,000 RPS. Median latency was 0.2ms at 50 concurrent connections, 1.5ms at 200 concurrent. The Python backend was the bottleneck — direct benchmarking against it gave the same throughput, meaning proxy overhead was indistinguishable from noise.

`perf record` with 59k samples confirmed the hot path is clean. No single function dominates:

```
~10%   kernel (epoll, read/write syscalls)
 2.0%  malloc + _int_malloc + cfree  (DashMap entries for new IPs)
 0.8%  tokio scheduler
 0.6%  handle_request (our code)
 0.5%  hyper client::send_request
 0.5%  hyper server::Connection::poll
 0.3%  pow (EWMA floating point math)
```

The proxy's own request handler is 0.6% of CPU. Heap allocation at ~2% comes from DashMap entries for per-IP rate limiting — amortized across requests from the same IP. No suspicious allocation patterns, no hotspots.

## Project structure

```
crates/upstreamer/src/
  main.rs        CLI, tokio runtime, spawns all background tasks
  config.rs      TOML types, validation
  balance.rs     OriginState, LoadBalancer trait, 3 implementations
  route.rs       Router, host/path matching, k8s origin merging
  server.rs      hyper proxy server, body collection
  state.rs       AppState (ArcSwap, DashMap, shared client)
  ratelimit.rs   TokenBucket, RateLimiter
  health.rs      active checker, /healthz endpoints
  metrics.rs     Prometheus recorder, self-metrics from /proc
  discovery.rs   k8s Service watcher
  reload.rs      config file hot-reload
  errors.rs      custom error page store
```

## What I'd do differently

The full-body collection before forwarding is the biggest v1 gap. For a proxy, streaming bodies is table stakes — the current approach works for small payloads but breaks down for large file uploads or chunked streaming responses. The hyper API supports it via `Body` implementations; it just needs the plumbing.

The Kubernetes discovery could be richer. Watching EndpointSlices instead of Services would give pod-level awareness, which matters for heterogeneous clusters where individual pods have different capacities. The trade-off is complexity — you're now duplicating kube-proxy.

The metrics histogram quantiles are cosmetic — the summary window ages out samples between scrape intervals, so `p50` shows 0 unless you happen to hit it during active traffic. Switching to explicit bucket boundaries (Prometheus histogram) would fix this and enable aggregation across instances.

## Running it

```toml
listen = "0.0.0.0:8080"
metrics_addr = "0.0.0.0:9090"

[[routes]]
match_path = "/"
lb_algorithm = "round_robin"

[[routes.pools]]
name = "backend"

[[routes.pools.origins]]
url = "http://127.0.0.1:3000"
```

```bash
cargo run -- --config upstreamer.toml
```

Health at `http://localhost:9090/healthz`, metrics at `http://localhost:9090/metrics`, proxy at `http://localhost:8080`.
