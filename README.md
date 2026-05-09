# upstreamer

![rust](https://img.shields.io/badge/rust-2024-orange?logo=rust)
![license](https://img.shields.io/badge/license-MIT-blue)

a reverse proxy in rust with kubernetes-native service discovery, hot config reload, and load balancing.

> **want the full story on how i built this?** check out my blog post: [https://blog.guswid.com/upstreamer](https://blog.guswid.com/upstreamer)

because the quick version wasn't good enough.

## features

- **TOML configuration with hot-reload** — file watcher swaps config atomically via arcswap. no restart required. bad config never crashes the proxy.
- **per-ip token bucket rate limiting** — global and per-route. stale buckets evicted by periodic cleanup. toctou-free consumption via the dashmap entry api.
- **kubernetes upstream discovery** — watches `v1::Service` objects with label selectors. services annotated with `upstreamer/pool` map to origin urls automatically.
- **host and path routing** — host matching with glob support, path prefix matching. multiple pools per route.
- **three load balancing algorithms** — round-robin (atomic counter), weighted-latency (ewma, α = 0.1), weighted-metrics (falls back to latency-weighted in v1).
- **prometheus metrics** — separate port with process rss/cpu/fds and per-origin proxy latency histograms.
- **active and passive health checking** — periodic probes and in-band failure tracking. configurable thresholds for marking origins healthy/unhealthy.
- **custom error pages** — configurable directory with status code to file mappings.
- **lock-free reads** — arcswap for config/router, dashmap for origin state. the hot path never blocks on a config update.

## prerequisites

- rust toolchain (2024 edition)
- linux (tested on nixos)

## installation

```sh
git clone https://github.com/GustavoWidman/upstreamer.git
cd upstreamer
cargo build --release
```

## usage

```sh
./target/release/upstreamer --config upstreamer.toml
```

validate config without starting:

```sh
./target/release/upstreamer --config upstreamer.toml --validate
```

### minimal config

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

## config reference

### top-level

| field | type | default | description |
|---|---|---|---|
| `listen` | string | `"0.0.0.0:8080"` | proxy listen address |
| `metrics_addr` | string | `"0.0.0.0:9090"` | health/metrics listen address |
| `ratelimit` | table | — | global rate limit (optional) |
| `health` | table | — | health check config (optional) |
| `kubernetes` | table | — | k8s discovery config (optional) |
| `error_pages` | table | — | custom error pages (optional) |
| `routes` | array | — | route definitions |

### ratelimit

| field | type | description |
|---|---|---|
| `rate` | u64 | tokens added per second |
| `burst` | u64 | maximum tokens (burst capacity) |

### health.active

| field | type | default | description |
|---|---|---|---|
| `enabled` | bool | `false` | enable active probing |
| `interval` | duration | `"10s"` | time between probes |
| `timeout` | duration | `"5s"` | probe timeout |
| `healthy_threshold` | u32 | `2` | consecutive successes to mark healthy |
| `unhealthy_threshold` | u32 | `3` | consecutive failures to mark unhealthy |

### health.passive

| field | type | default | description |
|---|---|---|---|
| `enabled` | bool | `false` | enable passive tracking |
| `failure_threshold` | u32 | `5` | consecutive failures to mark unhealthy |
| `success_threshold` | u32 | `2` | consecutive successes to mark healthy |
| `observation_window` | duration | `"60s"` | window for tracking failures |

### routes[]

| field | type | default | description |
|---|---|---|---|
| `match_host` | string | `"*"` | host matching (supports `*` glob) |
| `match_path` | string | `"/"` | path prefix matching |
| `lb_algorithm` | string | `"round_robin"` | `round_robin`, `weighted_latency`, or `weighted_metrics` |
| `ratelimit` | table | — | per-route rate limit (optional) |
| `pools` | array | — | pool definitions for this route |

### routes[].pools[]

| field | type | description |
|---|---|---|
| `name` | string | pool identifier (used by k8s discovery) |
| `origins` | array | origin definitions |

### routes[].pools[].origins[]

| field | type | default | description |
|---|---|---|---|
| `url` | string | — | origin url (http only) |
| `weight` | u32 | `1` | weight for load balancing |
| `health_check_path` | string | `"/"` | path for active health probes |

### kubernetes

| field | type | description |
|---|---|---|
| `namespace` | string | namespace to watch |
| `label_selector` | string | label selector for services |

services must have the annotation `upstreamer/pool` set to a pool name.

### error_pages

| field | type | description |
|---|---|---|
| `directory` | string | path to error page html files |
| `pages` | array | status code to file mappings |

## load balancing algorithms

**round-robin** — atomic counter, skips unhealthy origins. simple and predictable.

**weighted-latency** — ewma latency tracking (α = 0.1). weight = `1 / (latency_ns + 1)`. weighted random selection. good for heterogeneous backends where latency varies.

**weighted-metrics** — designed to factor in pod pressure from metrics-server. falls back to latency-weighted behavior when pressure data is unavailable (v1).

## benchmark

50 concurrent connections, 500k requests, localhost hyper backend, 14 cores (macos):

| proxy | RPS | p50 | p99 | p99.9 | p99.99 | slowest |
|---|---|---|---|---|---|---|
| backend (direct) | 154,998 | 0.32ms | 0.41ms | 0.95ms | 3.39ms | 3.57ms |
| **upstreamer** | **76,663** | **0.64ms** | **0.79ms** | **1.83ms** | **3.81ms** | **5.38ms** |
| haproxy | 70,503 | 0.70ms | 0.92ms | 1.95ms | 5.21ms | 8.24ms |
| nginx (auto) | 69,477 | 0.70ms | 1.01ms | 2.15ms | 7.25ms | 9.14ms |
| nginx (1 worker) | 68,637 | 0.76ms | 0.86ms | 2.05ms | 4.78ms | 4.97ms |
| caddy | 66,195 | 0.72ms | 1.66ms | 2.53ms | 6.97ms | 11.94ms |
| apache | 57,518 | 0.85ms | 1.38ms | 2.53ms | 7.21ms | 7.32ms |

1st in throughput. best tail latency of every proxy tested (p99.99 3.81ms, slowest request 5.38ms). beats haproxy by 8.7%, nginx auto by 10%, caddy by 2.4x on throughput. p99.99 is 27% better than haproxy and 47% better than nginx auto.

the throughput lead comes from tokio's work-stealing runtime scaling well across cores: parallel accept, concurrent task scheduling, and efficient arc atomics for shared state. nginx auto matches core count but still runs per-process epoll loops with cross-process coordination for shared state.

run your own comparison:

```sh
just bench-compare
```

## endpoints

| path | port | description |
|---|---|---|
| `/` | 8080 | proxy (forward to configured origins) |
| `/healthz` | 9090 | json health status |
| `/healthz/upstreams` | 9090 | per-origin health detail |
| `/metrics` | 9090 | prometheus text exposition |

## metrics

| metric | type | description |
|---|---|---|
| `upstreamer_process_resident_memory_bytes` | gauge | rss from `/proc/self/statm` |
| `upstreamer_process_cpu_seconds_total` | gauge | cpu time from `/proc/self/stat` |
| `upstreamer_process_open_fds` | gauge | open file descriptors |
| `upstreamer_total_origins` | gauge | total configured origins |
| `upstreamer_healthy_origins` | gauge | origins marked healthy |
| `upstreamer_proxy_request_duration_nanoseconds` | summary | per-origin proxy latency |

## testing

```sh
cargo test                       # unit tests
cargo clippy -- -D warnings      # lint
```

e2e tests (behave, python bdd):

```sh
just e2e
```

20 scenarios across 7 feature files: round-robin distribution, host and path routing, per-ip and per-route rate limiting, passive health failover, weighted-latency balancing, config hot-reload, and kind-based Kubernetes smoke coverage.

## v1 limitations

- no TLS
- no WebSocket
- no streaming request bodies (response bodies stream, requests are collected)
- global rate limiter not hot-swappable
- k8s metrics-server integration stubbed (weighted_metrics falls back to latency)

## license

[MIT](LICENSE)
