# upstreamer

A reverse proxy in Rust with Kubernetes-native service discovery, hot config reload, and production-grade observability. Built as a portfolio piece — the "doing it properly" version of a one-hour interview prompt.

## features

- TOML configuration with file-watcher hot-reload (no restart required)
- Per-IP token bucket rate limiting (global and per-route)
- Kubernetes upstream discovery via `v1::Service` watches
- Routing on host (glob) and path (prefix), multiple pools per route
- Load balancing: round-robin, weighted-latency (EWMA), weighted-metrics
- Prometheus metrics on a separate port (process RSS/CPU/FDs, per-origin latency)
- Active health probing + passive failure tracking
- Custom error pages from a configurable directory
- Lock-free config/router swap via `ArcSwap`
- Zero per-request allocations on the hot path

## build

```sh
cargo build --release
```

## run

```sh
upstreamer --config upstreamer.toml
```

Validate config without starting:

```sh
upstreamer --config upstreamer.toml --validate
```

## minimal config

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
| `listen` | string | `"0.0.0.0:8080"` | Proxy listen address |
| `metrics_addr` | string | `"0.0.0.0:9090"` | Health/metrics listen address |
| `ratelimit` | table | — | Global rate limit (optional) |
| `health` | table | — | Health check config (optional) |
| `kubernetes` | table | — | K8s discovery config (optional) |
| `error_pages` | table | — | Custom error pages (optional) |
| `routes` | array | — | Route definitions |

### ratelimit

| field | type | description |
|---|---|---|
| `rate` | u64 | Tokens added per second |
| `burst` | u64 | Maximum tokens (burst capacity) |

### health.active

| field | type | default | description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable active probing |
| `interval` | duration | `"10s"` | Time between probes |
| `timeout` | duration | `"5s"` | Probe timeout |
| `healthy_threshold` | u32 | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | u32 | `3` | Consecutive failures to mark unhealthy |

### health.passive

| field | type | default | description |
|---|---|---|---|
| `enabled` | bool | `false` | Enable passive tracking |
| `failure_threshold` | u32 | `5` | Consecutive failures to mark unhealthy |
| `success_threshold` | u32 | `2` | Consecutive successes to mark healthy |
| `observation_window` | duration | `"60s"` | Window for tracking failures |

### routes[]

| field | type | default | description |
|---|---|---|---|
| `match_host` | string | `"*"` | Host matching (supports `*` glob) |
| `match_path` | string | `"/"` | Path prefix matching |
| `lb_algorithm` | string | `"round_robin"` | `round_robin`, `weighted_latency`, or `weighted_metrics` |
| `ratelimit` | table | — | Per-route rate limit (optional) |
| `pools` | array | — | Pool definitions for this route |

### routes[].pools[]

| field | type | description |
|---|---|---|
| `name` | string | Pool identifier (used by k8s discovery) |
| `origins` | array | Origin definitions |

### routes[].pools[].origins[]

| field | type | default | description |
|---|---|---|---|
| `url` | string | — | Origin URL (http only) |
| `weight` | u32 | `1` | Weight for load balancing |
| `health_check_path` | string | `"/"` | Path for active health probes |

### kubernetes

| field | type | description |
|---|---|---|
| `namespace` | string | Namespace to watch |
| `label_selector` | string | Label selector for Services |

Services must have the annotation `upstreamer.ora.ooo/pool` set to a pool name.

### error_pages

| field | type | description |
|---|---|---|
| `directory` | string | Path to error page HTML files |
| `pages` | array | Status code to file mappings |

## load balancing algorithms

**round_robin** — atomic counter, skips unhealthy origins. Simple and predictable.

**weighted_latency** — EWMA latency tracking (α = 0.1). Weight = `1 / (latency_ns + 1)`. Weighted random selection. Good for heterogeneous backends where latency varies.

**weighted_metrics** — designed to factor in pod pressure from metrics-server. Falls back to latency-weighted behavior when pressure data is unavailable (v1).

## endpoints

| path | port | description |
|---|---|---|
| `/` | 8080 | Proxy (forward to configured origins) |
| `/healthz` | 9090 | JSON health status |
| `/healthz/upstreams` | 9090 | Per-origin health detail |
| `/metrics` | 9090 | Prometheus text exposition |

## metrics

| metric | type | description |
|---|---|---|
| `upstreamer_process_resident_memory_bytes` | gauge | RSS from `/proc/self/statm` |
| `upstreamer_process_cpu_seconds_total` | gauge | CPU time from `/proc/self/stat` |
| `upstreamer_process_open_fds` | gauge | Open file descriptors |
| `upstreamer_total_origins` | gauge | Total configured origins |
| `upstreamer_healthy_origins` | gauge | Origins marked healthy |
| `upstreamer_proxy_request_duration_nanoseconds` | summary | Per-origin proxy latency |

## testing

```sh
cargo test              # unit tests
cargo clippy -- -D warnings   # lint
```

E2e tests with kind:

```sh
./e2e/run.sh
```

Requires Docker daemon running.

## benchmark

With a warm connection pool proxying to a localhost backend:

- ~115,000 RPS throughput
- p50 latency: 0.2ms at 50 concurrent connections
- RSS: 8.5 MB cold, 14.8 MB warm, stable through 250k+ requests

## v1 limitations

- No TLS
- No WebSocket
- No streaming bodies (full collection before forwarding)
- Global rate limiter not hot-swappable
- k8s metrics-server integration stubbed (weighted_metrics falls back to latency)

## license

MIT
