# Architecture

upstreamer is a reverse proxy and static file server for NixOS hosts. You configure it with
Nix options, the NixOS module writes one JSON file, and `upstreamer check` validates that file
when the system builds. At run time one thread per CPU serves HTTP/1.1, HTTP/2 and HTTP/3 over
TLS, and every protocol feeds the same request pipeline.

Functions whose body is `todo!()` are not built yet. Their doc comments state the contract
that the implementation has to meet.

## The request path

Data moves through these types, in the order a request meets them:

1. `config::Config` is the JSON schema. It is the only definition of the config language.
2. `plan::compile::compile` turns a config into a `plan::Plan`. The plan is immutable and
   shared by every core through an `Arc`. Vars, regexes, origins and sites are indices in it,
   includes are spliced, and templates are parsed.
3. Each core builds a `runtime::CoreSnapshot` from the plan when a new generation arrives. The
   snapshot holds the core's own rustls configs.
4. A protocol driver (`proto::h1::server`, `proto::h2`, `proto::h3`) fills an
   `exchange::Exchange` with the request head (`msg::RequestHead`) and calls
   `pipeline::handle`.
5. `pipeline::handle` picks the site by listener and host, then runs `route::run`. The router
   is a pure function over the plan and the exchange. It returns a `route::Outcome`, with
   every template already expanded into the exchange's arena.
6. The pipeline answers the outcome with `proxy::forward`, `files::serve`, a local response, a
   redirect or an error. An error status goes through the site's error routes.
7. `pipeline::finalize` applies the header edits in one fixed order, and the driver writes the
   `pipeline::Response`. Its `body::Body` is a closed enum, so each driver picks the cheapest
   transfer for each kind of body: writev, sendfile, an in-place relay, or DATA frames.
8. For a site with an access log, the pipeline also returns an `access::Started`, and the
   driver completes it with `access::record` once the response or tunnel is over.

## Modules

The crate is one library with private modules. Its public items are `run`, `check`,
`Diagnostic` and their argument and result types, in `src/lib.rs`. `src/main.rs` is the
command line.

| file | owns |
|---|---|
| `src/config.rs` | the JSON schema and its parsers, with errors that carry the JSON pointer of the failing value |
| `src/plan/mod.rs` | the compiled plan's types, `Diagnostic`, and `check` |
| `src/plan/compile.rs` | config to plan: includes, var interning, templates, matchers, origins, listeners |
| `src/plan/cond.rs` | compiled matchers |
| `src/plan/host.rs` | host to site lookup per listener |
| `src/plan/template.rs` | template parsing and expansion |
| `src/route.rs` | the step interpreter and matcher evaluation |
| `src/msg.rs` | request and response heads, header fields, clean paths, rewrites |
| `src/exchange.rs` | per-request state, its arena, and the per-core exchange pool |
| `src/body.rs` | response and request bodies |
| `src/pipeline.rs` | site choice, error routes, header finalisation |
| `src/proto/h1/codec.rs` | HTTP/1.1 parsing, framing and serialisation, without IO |
| `src/proto/h1/server.rs` | the HTTP/1.1 connection driver |
| `src/proto/h1/client.rs` | the upstream request head |
| `src/proto/h2/` | the HTTP/2 connection engine (frames, HPACK, flow control, limits) and its driver |
| `src/proto/h3.rs` | the HTTP/3 driver on the `quinn` and `h3` crates |
| `src/proxy/mod.rs` | forwarding to an origin, dialling, the retry rule |
| `src/proxy/pool.rs` | per-core idle upstream connections |
| `src/proxy/relay.rs` | body relays and upgraded tunnels |
| `src/files/mod.rs` | the static file server |
| `src/files/catalog.rs` | the per-core cache of file facts, descriptors and small files |
| `src/files/negotiate.rs` | content coding choice, conditionals, ranges, content types |
| `src/encode.rs` | dynamic compression |
| `src/tls/mod.rs` | the certificate store, server and client configs, session tickets, handshakes |
| `src/tls/ktls.rs` | kernel TLS offload |
| `src/net/mod.rs` | sockets and transports |
| `src/net/listen.rs` | per-core listening sockets |
| `src/net/buf.rs` | per-core buffer pools |
| `src/runtime/mod.rs` | cores, generations, snapshots |
| `src/runtime/control.rs` | startup, reload, shutdown, systemd notification |
| `src/access.rs` | access log lines, the files of a generation, and each core's buffered writer |
| `src/log.rs` | logging to stderr with journald priority prefixes |

## Seams

Several modules are built at the same time against these types and signatures. Change one
only together with every module that uses it.

- `msg`: `RequestHead`, `ResponseHead`, `Fields`, `Known`, `HeaderName`, `Status`, `Method`,
  `CleanPath`, `clean_path`. A head keeps everything in one buffer that its exchange recycles.
  Producers fill a request head with `set_line`, `push_field` and `set_host`.
- `exchange`: `Exchange`, `ConnInfo`, `Arena`, `ASpan`, `Pending`, `ExchangePool`.
- `body`: `Body` and `RequestBody`.
- `config`: every schema type, `parse_config` and `parse_fragment`.
- `plan`: `Plan`, `SitePlan`, `Block`, `Step`, `Action`, `Terminal`, the `*Plan` types,
  `ListenerKey`, `CertSource`, `ServerParams` and the id types.
- `pipeline::handle(core, snapshot, exchange, body) -> (Response, Option<access::Started>)`,
  which every driver calls, and `access::record(core, snapshot, exchange, started, status,
  bytes)`, which it calls once the response is sent.
- `net::Socket`: `from_fd`, `connect`, `read`, `write_all_vectored`, `readable`,
  `hung_up_or_readable`, `sendfile`, `fd`.
- `route::{run, run_error, Outcome, Effects}`, `files::serve`, `encode::{decide, wrap}`,
  `tls::{load, CertStore, server_config}`.

## Invariants the types carry

- Only `msg::clean_path` and the head's own edits make a `CleanPath`. It is decoded and has no
  `.` or `..` segment, so a file root joined with it cannot escape the root.
- `msg::Target::Original` means the client's request-target goes upstream byte for byte. Only
  `rewrite` and a `stripPrefix` the raw bytes cannot follow switch to `Target::Rebuilt`, so
  signed S3 requests keep their signature.
- A step has exactly one action. The schema rejects a second one, so a misspelt key is an
  error and never a different step.
- `{re.N}` reads the capture group of the regex in the same step's `when`. Captures are
  cleared before every step.
- Config header operations cannot name framing headers (`msg::Known::framing`). The codec
  writes those.
- Listeners and certificate names are derived from the sites. Nothing lists them twice.
- `route::Outcome` borrows only the plan, and everything per request lives in the exchange.

## Threads and reload

`runtime` runs one pinned thread per CPU in the process's affinity mask. Each thread runs a
current-thread tokio runtime and binds its own `SO_REUSEPORT` socket per address. Connections,
upstream pools, buffer and exchange pools, regex caches, the file catalog and the coarse clock
belong to one core and are `!Send`. Cores share only immutable `Arc`s.

The control thread is the main thread. It compiles plans, loads certificates and publishes a
`runtime::Generation` to every core. A connection reads `Core::snapshot` once per request, so
a reload applies to the next request of each connection, and a request in flight finishes
under the plan it started with. A reload whose config fails to parse or compile keeps the
running generation.

## Access logs

A site with `accessLog` gets one JSON object per line for every request it answers and every
tunnel once it closes. `src/access.rs` documents the fields, and the NixOS option
`accessLog.enable` repeats them for the people who read the files.

The control thread opens the plan's log files in append mode at startup and at every reload,
and publishes them in the `runtime::Generation`. A reload therefore reopens every file, which
is how logrotate's rename and `postrotate` reload start a new one. A file that cannot be opened
does not fail the reload: the systemd status names it, and its lines are counted as dropped.

The per-request cost is paid only by sites that log. Once the pipeline has chosen such a site,
it reads the monotonic clock and formats the request's fields into the exchange's arena, before
any rewrite. When the response ends, the driver passes the status and the body bytes it sent.
The core's `access::Writer` adds the time, status, bytes, duration and origin, and appends the
whole line to its buffer for that file. Nothing allocates once the buffers have grown, and
nothing makes a syscall per request. A buffer is written with a single `write(2)` once it passes
32 KiB, on the core's one-second clock tick, before the core adopts a new generation's files,
and when the core stops. Each buffer holds whole lines and the file is in append mode, so lines
of different cores never interleave inside a line. A failed or short write drops the lines it
did not write. The core logs a warning with the count once a second, and no request waits for
the disk.

## TLS certificates

`tls::load` never fails as a whole. For a source whose pair is missing, unreadable or does not
match its key, each name keeps its previous certificate from files. A name that never had one
gets an in-memory self-signed certificate for that name, until a reload finds a usable pair.
The NixOS module reloads the service when ACME renews a certificate, and reload re-reads every
pair.

## Configuration and Nix

The NixOS module lives in `nix/module.nix`. Virtual hosts are Nix options. Routes are JSON
values in the schema of `src/config.rs`, and the module does not restate that schema in Nix.
The module writes the config with `builtins.toJSON` and runs `upstreamer check` on it while
the system builds, so a bad route fails the build with its JSON pointer and step name. A
package can generate route fragments at build time, and a host names them with an `include`
step, so Nix never reads the generated file.

The flake is built from these files:

- `flake.nix` lists the inputs and imports the files below.
- `nix/toolchain.nix` pins Rust through `rust-toolchain.toml` with fenix.
- `nix/package.nix` builds the package with crane and defines the test, clippy and rustfmt
  checks.
- `nix/shell.nix` is the dev shell.
- `nix/module.nix` is the NixOS module.
- `nix/examples/` holds example hosts and the checks that evaluate the module for them.

`checks.<system>.module-eval` evaluates each example host without building anything. It
compares the certificates, groups, unit, firewall and kernel modules the module derives with
expected values, and the emitted config with `tests/fixtures/config/<host>.json`. After you
change the module or an example host, run `fixtures` in the dev shell to rewrite those files.
On Linux, `checks.<system>.module-config` also builds each example's checked config file.

## Testing

Run these in the dev shell (`nix develop`):

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
nix flake check --no-build
```

`tests/check.rs` runs `check` on the example configs and on the generated fragments in
`tests/fixtures/site/upstreamer`, where `@out@` stands for the site package's store path.
`tests/cli.rs` covers the exit codes of the command line.
