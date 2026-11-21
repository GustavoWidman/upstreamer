# Proxy benchmark harness

Measures upstreamer against the popular reverse proxies on one Linux host, with
every tool pinned by the flake. It decides performance claims, so each run
records enough to answer, after the fact: what limited it, whether every
request succeeded and reached the origin, whether the load generator or the
origin was the bottleneck, and whether the host was disturbing it.

Run it on Linux only: the x86_64 bench VM with the `fleet` and `wide`
profiles, or a 2-vCPU aarch64 host (the fleet's own hardware) with the `pair`
profile. Never benchmark on macOS. On aarch64 the toolchain has no wrk2, which
does not build there, so only closed-loop runs work.

## Commands

All commands run through the flake app; `just bench <args>` is the same thing.
Results go to `--out` (default `$BENCH_OUT`, else `./bench-results`).

| Command | What it does |
|---|---|
| `nix run .#bench -- run --mode both` | Full matrix: every scenario, every server that supports it, `fleet` and `wide` profiles, 5 interleaved repetitions, closed loop, then open loop at rates derived from the closed loop. Writes `summary-<label>.md` and `.json`. |
| `nix run .#bench -- run --scenarios h1,h2-tls --servers nginx,haproxy --profiles fleet` | A subset. `--servers` takes `all`, `competitors` or a list. |
| `nix run .#bench -- refresh --scenarios h1 --mode both` | Re-measures the competitors (label `baseline`) and rewrites `summary-baseline.json`, the stored medians `quick` compares against. |
| `nix run .#bench -- quick --upstreamer-src ~/wt/u1 --against bench-results/summary-baseline.json --scenarios h1 --profiles fleet` | Builds upstreamer from that tree, runs only upstreamer (5 reps), prints its median and range next to the best stored competitor, with the margin and whether the ranges are disjoint. |
| `nix run .#bench -- profile --server upstreamer --scenario h1 --profile fleet` | Runs the scenario under `perf record` on the proxy's processes and writes `flamegraph.svg` and `stacks.folded` under `profiles/`. Profiled runs never enter the results. |
| `nix run .#bench -- serve --server caddy [--scenarios features] [--hold]` | Starts the origin and one server and probes every scenario it supports, restarting the server for each feature scenario's config. Use it when writing a config. |
| `nix run .#bench -- report [--label baseline]` | Re-summarizes the stored JSONL. |
| `nix run .#bench -- tuning` | Every server's version, settings applied, sources and n/a reasons. |

`--scenarios` takes `all`, `core` (the scenarios without proxy features),
`features` (the feature scenarios and `h1-hdr`, their keyed reference), or a
comma list.

Useful options: `--reps`, `--warmup` (s, default 3), `--duration` (s, default
10), `--label`, `--quiet-wait` (s to wait for a quiet host before each run,
default 3600, `0` skips), `--retries` (default 2), `--upstreamer-src` (default
the current directory), `--rates FILE` (open-loop rates as
`{profile: {scenario: req/s}}`).

## Topology

One host, three roles on disjoint vCPU sets, pinned with `taskset`. Each role
runs in its own transient systemd user scope, so CPU seconds and peak memory
come from its cgroup and cover every process and thread it spawns.

| Profile | proxy | origin | load generator | spare (client-heavy scenarios) |
|---|---|---|---|---|
| `fleet` | 2-3 | 4-6 | 7-10 | 11-12 |
| `wide` | 2-4 | 5-7 | 8-11 | 12-14 |
| `single` | 2 | 4-6 | 7-10 | 11-12 (sensitivity check only) |
| `pair` | 1 | 0 | 0 | none (2-vCPU hosts) |

`fleet` mirrors the 2-core production hosts. `wide` is 3 proxy vCPUs because
the bench VM's 16 vCPUs share a power-limited 8-core mobile CPU: at 8 busy
vCPUs a pinned spin loop runs at 0.68 of its single-vCPU speed and the
whole VM delivers about 5.5 single-vCPU equivalents. Measured with nginx on
`h1`: 3 proxy vCPUs gave 76k req/s with no steal on the proxy and 20% idle
left on the origin. 4 gave 87k, but with 10% steal on the proxy's vCPUs and
the origin under 10% idle, so the number measured the host. 6 and 8 fell to
72k and 74k.
`pair` is for a host with 2 vCPUs: every server runs one worker on vCPU 1,
and the origin, the load generator and the harness itself share vCPU 0. Its
`loadgen_saturated` and `origin_saturated` flags both read vCPU 0, so they say
the client side, not the proxy, set the number; compare against `direct` on
`h1` for the client side's own ceiling. Its quiet gate and `foreign_load`
limit are 0.2 cores, since 1.5 foreign cores would be most of the host.
`custom:p=2-3:o=4-6:l=7-8` builds an ad-hoc layout for harness checks.

The origin (`bench/origin`) is a small HTTP/1.1 server: one thread per vCPU,
each with its own `SO_REUSEPORT` listener per address. It answers on two
addresses (ports 18080 and 18081), the second for the scenarios that balance
over two origins. `GET /bytes/<n>` returns n bytes, request bodies
(Content-Length or chunked) are read and discarded, and `/__stats` reports
request and byte counters, with the requests each address took, which the
harness reads around every measured window.

## Scenarios

Each has a name and a version. Bump the version when anything that moves its
numbers changes; the report never mixes versions.

| Scenario | What | Load generator |
|---|---|---|
| `h1` | HTTP/1.1 cleartext, keep-alive, 1 KiB response, 256 connections | wrk / wrk2 |
| `h1-tls` | Same over TLS 1.3 | wrk / wrk2 |
| `h2-tls` | HTTP/2 over TLS 1.3, 32 connections x 8 streams | h2load |
| `h3` | HTTP/3, 32 connections x 8 streams | h2load (ngtcp2) |
| `tls-handshake` | Full TLS 1.3 handshake per request (new connection each time), 64 concurrent | oha (rustls) on load generator plus spare vCPUs |
| `static-h2` | 1 KiB file from the server's own file server over TLS + HTTP/2 | h2load |
| `large-response` | 1 MiB response over TLS, keep-alive, 32 connections | wrk / wrk2 |
| `large-upload` | 1 MiB POST body over TLS, keep-alive, 32 connections | wrk / wrk2 |
| `idle-tls` | 10,000 TLS keep-alive connections, one request each, held idle; proxy memory | `harness.idle_client` |

### Feature scenarios

The same load as `h1` (or `h2-tls`) with proxy features on, so a feature's
cost is the ratio of its cell to the plain one, and the comparison covers only
the servers that ship the feature. A scenario that sends a client key reads
its cost against `h1-hdr`, which sends the same key header with no feature
on: the proxy parses and forwards that header whether a feature reads it or
not, so against plain `h1` the ratio would also charge the feature for it.

| Scenario | Features |
|---|---|
| `h1-hdr` | none; every request carries `X-Client` as in `h1-limit` (the reference of `h1-lb2-hash` and `h1-limit`) |
| `h1-lb2` | round robin over the origin's two addresses |
| `h1-lb2-least` | fewest requests in flight over the two addresses |
| `h1-lb2-hash` | consistent hash of the `X-Client` header over the two addresses |
| `h1-limit` | a rate limit with one bucket per `X-Client` value, never rejecting |
| `h1-limit-const` | a rate limit with one bucket for every request, never rejecting |
| `h1-metrics` | request metrics on, the endpoint scraped every 5 s during the run |
| `h1-all` | round robin over two health-checked addresses, a per-client limit keyed on the address a trusted peer forwards in `X-Forwarded-For`, metrics scraped |
| `h2-tls-all` | `h1-all` over HTTP/2 |

wrk sends each request with the next of 1024 client keys (`X-Client: c<k>`,
or `X-Forwarded-For: 10.0.x.y`), from a Lua `request()` that picks one of 1024
requests formatted in `init`. h2load sends fixed headers, so `h2-tls-all` has
one client for the whole run. The limits run at 1,000,000 req/s, per key and
for the single bucket (the most upstreamer accepts), about five times what
the host can drive:
the bookkeeping is measured, never a refusal (a 429 is an error). Active
health checks probe `GET /bytes/2` every 10 s.

A server takes part only if it has an equivalent of every feature in the
scenario. upstreamer, nginx, haproxy, caddy, envoy and traefik have feature
configs (`servers/*-features*`, filled per scenario by the server's module);
`tuning` lists what each one runs and why a feature is n/a. A scenario
without features renders each server's usual config byte for byte.

Each balanced run must send at least 20% of the requests to each origin
address, and each scrape must answer 200 with a body; otherwise the run is
flagged `work_mismatch`.

Every TLS client sends SNI `localhost` and negotiates TLS 1.3 with the
default groups (X25519MLKEM768 where both sides support it). All servers use
the same ECDSA P-256 certificate.

**Closed loop** (`--mode closed`) measures maximum throughput.
**Open loop** (`--mode open`) offers a fixed rate, half the slowest
competitor's closed-loop median for that scenario and profile, and ranks by
p99. wrk2 and oha (`--latency-correction`) correct latency for coordinated
omission; h2load does not.

wrk's OpenSSL 3 client spends about 2.2 ms of CPU per full handshake, against
about 0.37 ms for oha's rustls client (measured against nginx on 6 vCPUs: 2.4k
handshakes/s with wrk on 5.4 busy vCPUs, 3.8k/s with oha on 1.4), so the
handshake scenario uses oha; wrk stays on keep-alive scenarios, where it
handshakes once per connection.

## Servers

Competitors live in `harness/competitors/<name>.py` with their config template
in `servers/`. nginx (mainline), haproxy, caddy, envoy (upstream binary),
traefik (upstream stable binary), h2o, Apache httpd (event MPM), lighttpd,
sozu, ferron. `nix run .#bench -- tuning` prints each one's settings, the
vendor documentation behind them, and why it is n/a where it is. `direct`
sends the load straight at the origin and gives the ceiling every proxy is
measured under.

upstreamer is launched by `harness/upstreamer.py`, the only file that knows
its build command, config format and capabilities. A rebuilt upstreamer with
a new config format, TLS, HTTP/2, HTTP/3 or a file server plugs in by changing
that file alone.

To add a competitor, add its package to `nix/bench.nix`, a template to
`servers/`, and a module exposing `SERVER` to `harness/competitors/`; `serve`
must print `ok` for every scenario it claims.

## One run

1. Wait until the host's task CPU use (everything except the idle origin) is
   under 1 core (0.2 on `pair`) for 2 s (lab is shared).
2. Start the server in its scope; probe the scenario's protocol and path with
   4 requests until all return 2xx with the expected body size.
3. Warm up for `--warmup` seconds with the same load, then measure for
   `--duration` seconds while sampling the proxy's PSS and cgroup memory.
4. Stop the server and append one JSON record to the session's
   `results.jsonl`. Records are only appended; a session file is created
   exclusively and never rewritten.

Repetitions are interleaved: for each repetition, every scenario runs every
server once, in an order rotated by one each repetition, so warm-up, drift
and thermal state favour no server. Runs the host disturbed are re-queued at
the end of the profile, and every attempt stays in the JSONL.

## What a record holds

Requests, req/s, bytes/s, latency p50/p99/p99.9/max/mean, errors (connect,
read, write, timeout, non-2xx, stream), origin request and body-byte deltas,
and per role (proxy, origin, load generator) the cgroup CPU seconds,
utilisation, and the idle, softirq, steal and foreign fractions of the role's
vCPUs from `/proc/stat`. Also the proxy's peak PSS and cgroup memory, load
average before and after, host-wide foreign and steal cores, the quiet-gate
wait, the tool versions (`session.json`), the harness git rev and, for
upstreamer, its source rev and dirty flag.

Softirq time (loopback packet processing) is charged to no cgroup, so a
role's saturation is read from its vCPUs' idle fraction, not from its cgroup
CPU time alone.

## Flags

A run is valid only without these:

- `errors`: any failed, timed-out or non-2xx request.
- `work_mismatch`: bytes per response off the expected body size, the origin's
  request count off the load generator's by more than the in-flight window,
  upload bytes missing at the origin, or (static) requests reaching the origin.
  For `idle-tls`: fewer than 10,000 connections answered, or one closed
  during the hold.
- `loadgen_saturated`: the load generator's vCPUs were under 10% idle (closed loop).
- `loadgen_failed`: the load generator exited non-zero.
- `foreign_load`: other processes used over 1.5 cores (0.2 on `pair`) host-wide, or (closed
  loop) over 10% of the proxy's vCPUs.
- `steal`: hypervisor steal over 5% of the proxy's vCPUs.

Informational: `proxy_below_saturation` (proxy vCPUs over 10% idle in closed
loop, so the proxy was not the limiter), `origin_saturated` (origin vCPUs
under 20% idle), `rate_missed` (open loop achieved under 95% of the target;
excluded from open-loop ranking).

## Report

Per scenario, profile and mode: each server's median and range over valid
runs, `n` valid and `bad` runs, latency medians, proxy utilisation and CPU
microseconds per request, and the load generator's peak utilisation. The
winner is the best median. upstreamer's margin to the best competitor is
reported with the combined spread (half of each range, summed) and a verdict:
better or worse with disjoint ranges, or no separation.

Some scenarios overcommit the VM by themselves: in `wide` `tls-handshake`
the client spends about as much CPU per handshake as the server, and the
fastest server's vCPUs see 7 to 9% steal on every attempt; in `wide`
`static-h2`, h2load on 4 vCPUs saturates near 480k req/s before h2o does.
When a server has no clean run and its runs failed only on such a host
ceiling, the report summarizes those runs and labels the row (with the steal
level, or as a lower bound when the load generator saturated), instead of
dropping the fastest server from the ranking.

## Instructions per request

`python3 -m harness.gate` (with the bench app's `PATH`, `BENCH_TOOLS` and
`PYTHONPATH`) compares upstreamer binaries by the user-space instructions the
proxy retires per request, A/B/B/A, under the same topology and configs:

```
python3 -m harness.gate --bin base=<a>/bin/upstreamer --bin head=<b>/bin/upstreamer \
  --scenarios h1,h1-tls,h2-tls,static-h2 --reps 6 --out bench-results --repo .
```

Instructions per request vary by about 0.1% from run to run, where req/s
needs disjoint ranges, so a regression of a few nanoseconds per request shows.
A proxied scenario counts the requests at the origin over a 10 s window; a
static one counts the load generator's requests, with perf wrapping the load
generator. Runs go to `gate.jsonl` in the session, never to the matrix's
results.

## Known noise

- The VM's vCPUs share a power-limited mobile CPU; total load sets the clock,
  so absolute numbers do not transfer to other machines. Rankings under equal
  conditions are what the harness decides.
- Other jobs on lab (CI runners, builds, a deployment daemon's dry-run
  builds). The quiet gate and the `foreign_load` and `steal` flags keep them
  out of the medians.
