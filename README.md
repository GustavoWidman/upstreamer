# upstreamer

A configurable reverse proxy in Rust with first-class Kubernetes integration.

## Features

- TOML-driven configuration with hot-reload
- Per-IP ratelimiting (token bucket, configurable rate + burst)
- Kubernetes upstream discovery via `Service` watches
- Routing on host, path, or both — multiple pools per route
- Selectable load-balancing: round-robin, weighted-by-latency, weighted-by-metrics
- Prometheus metrics on a separate port (CPU time, memory, open files, latency — self and per-upstream)
- Health checks (active probing + passive failure tracking, both configurable) on the metrics port
- Custom error pages
- No TLS (yet)

Status: early development. Inspired by a one-hour interview prompt. Now done properly.

## Build

```sh
cargo build --release
```

## Run

```sh
upstreamer --config upstreamer.toml
```

See `examples/` for sample configurations.
