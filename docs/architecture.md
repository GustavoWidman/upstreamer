# Architecture

upstreamer is a reverse proxy and static file server. On NixOS you configure it with Nix
options, the module writes one JSON file, and `upstreamer check` validates that file when the
system builds. Anywhere else you write the same schema as a TOML file, which
[config.md](config.md) documents. At run time one thread per CPU serves HTTP/1.1, HTTP/2 and HTTP/3 over
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
8. For a site that logs, or under a plan that collects metrics, the pipeline also returns an
   `observe::Started`, and the driver completes it with `observe::finish` once the response or
   tunnel is over.

Features the config does not name are absent from the plan, so the request path never tests
for them. A single origin without health settings is `plan::Target::Origin`; a site without a
`limit` step has no `plan::Action::Limit`; a plan without a `metrics` step stores no route
slot and gives no site an `Observe` for metrics; a plan without `trustedProxies` has no
`trust`; a plan without in-process ACME has no challenge step.

## Modules

The crate is one library with private modules. Its public items are `run`, `check`,
`convert`, `Diagnostic` and their argument and result types, in `src/lib.rs`. `src/main.rs` is the
command line.

| file | owns |
|---|---|
| `src/config/mod.rs` | the schema and its parsers (JSON or TOML by extension), with errors that carry the JSON pointer of the failing value |
| `src/config/toml.rs` | TOML to the JSON value of the same document, with positions for diagnostics |
| `src/config/toml/convert.rs` | the conversion itself, and JSON to TOML: the library reads TOML through it, and `upstreamer convert` reaches it through `upstreamer::convert` |
| `src/main.rs` | the command line: `run`, `check`, `example` and `convert`, and the summary `check` prints |
| `src/config/trust.rs`, `src/config/acme.rs` | the schema of `trustedProxies` and of in-process ACME |
| `src/plan/mod.rs` | the compiled plan's types and `Diagnostic` |
| `src/plan/load.rs` | reading a config into a plan for `run` and `check`, locating diagnostics, `check`'s costs |
| `src/plan/compile.rs` | config to plan: includes, var interning, templates, matchers, listeners |
| `src/plan/compile/upstream.rs` | proxy targets: origins by identity, pools by value |
| `src/plan/compile/limit.rs`, `src/plan/compile/key.rs` | `limit` steps, and the request keys of limits and hash balancing |
| `src/plan/compile/labels.rs` | route slots, the `metrics` step, each site's `Observe` |
| `src/plan/compile/trust.rs`, `src/plan/compile/acme.rs` | `trustedProxies`, and a site's `tls.acme` |
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
| `src/proxy/mod.rs` | forwarding to a target (one origin or a pool), dialling, the retry rule |
| `src/proxy/pool.rs` | per-core idle upstream connections, requests in flight and failures per origin, per-pool state, by `Upstreams` epoch |
| `src/upstream/mod.rs` | `Upstreams` (the origins and pool members of an epoch) and the control thread's `Registry` |
| `src/upstream/balance.rs`, `health.rs`, `tables.rs`, `maglev.rs` | picking an origin, health cells and probes, per-policy member tables |
| `src/key.rs` | request keys for hash balancing and limits |
| `src/limit.rs` | rate-limit tables shared by every core |
| `src/metrics/` | per-snapshot counters, the hub cores publish to, the exposition |
| `src/observe.rs` | what a finished request records: its access log line and its metrics |
| `src/discover/` | discovery sources (Kubernetes behind the `kubernetes` feature) |
| `src/trust.rs` | the client address a trusted proxy forwards |
| `src/acme/` | in-process ACME: the client on the control thread and the validation answers |
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
| `src/runtime/control.rs` | startup, reload, discovery and ACME publishes, shutdown, systemd notification |
| `src/access.rs` | access log line format, the files of a generation, and each core's buffered writer |
| `src/log.rs` | logging to stderr with journald priority prefixes |

## Seams

Several modules are built at the same time against these types and signatures. Change one
only together with every module that uses it.

- `msg`: `RequestHead`, `ResponseHead`, `Fields`, `Known`, `HeaderName`, `Status`, `Method`,
  `CleanPath`, `clean_path`. A head keeps everything in one buffer that its exchange recycles.
  Producers fill a request head with `set_line`, `push_field` and `set_host`.
- `exchange`: `Exchange`, `ConnInfo`, `Arena`, `ASpan`, `Pending`, `ExchangePool`.
- `body`: `Body` and `RequestBody`.
- `config`: every schema type, `Format`, `parse_config(format, bytes)` and
  `parse_fragment(format, bytes)`.
- `plan`: `Plan`, `SitePlan`, `Block`, `Step`, `Action`, `Terminal`, the `*Plan` types,
  `Target`, `OriginSpec` and `OriginKey`, `KeyPlan`, `RouteSlot`, `Observe`, `ListenerKey`,
  `CertSource`, `ServerParams` and the id types.
- `pipeline::handle(core, snapshot, exchange, body) -> (Response, Option<observe::Started>)`,
  which every driver calls, and `observe::finish(core, snapshot, exchange, started, status,
  bytes)`, which it calls once the response is sent.
- `upstream::{Upstreams, Origin, Members, Registry}`, `proxy::pool::{Pools, OriginLocal, Busy}`,
  `proxy::dial(core, upstreams, id, timeout)`.
- `runtime::{Generation, CoreSnapshot}` and `runtime::control::Live`: what each feature
  publishes to the cores and keeps across generations.
- `exchange::Exchange::{client, route, origin, refused, upstream}`.
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

`tls::load` never fails as a whole. A site's certificate comes from files or from in-process
ACME, whose client writes what it issues where the site's certificate source points. For a source whose pair is missing, unreadable or does not
match its key, each name keeps its previous certificate from files. A name that never had one
gets an in-memory self-signed certificate for that name, until a reload finds a usable pair.
The NixOS module reloads the service when ACME renews a certificate, and reload re-reads every
pair.

## Configuration, TOML and Nix

One schema, two syntaxes. The format follows the file's extension (`config::Format::of`).
`config::parse_config` reads JSON straight from its bytes, so serde_json's errors keep their
line and column. For TOML it first converts the document to a `serde_json::Value`
(`config::toml::to_json`) and runs the same deserializer over that value, so TOML cannot mean
something JSON could not, and every diagnostic has the same pointer, site, step and message in
both. The conversion also records where each value starts in the text, by JSON pointer.
`Diagnostic::locate` appends the position of the value a pointer names, or of its nearest
ancestor that has one, so a key the schema missed points at its table.

The only two differences are inherent. A TOML table has no `null`, so a header removal is
`false` (the schema reads `null` and `false` alike there). And `serde_json::Value` orders keys
alphabetically while a JSON file keeps its own order, so when one table has several mistakes the
TOML diagnostic names the one that sorts first.

`upstreamer convert` is the same conversion exposed: a `.toml` input becomes JSON, anything else
becomes TOML, and it writes `null` as `false` in a header map and drops it elsewhere.
`upstreamer example` prints one of the files in `examples/`, which `include_str!` embeds in the
binary and the tests check.

The NixOS module lives in `nix/module.nix`. Virtual hosts are Nix options. Routes are JSON
values in the schema of `src/config/mod.rs`, and the module does not restate that schema in Nix.
The module writes the config with `builtins.toJSON` and runs `upstreamer check` on it while
the system builds, so a bad route fails the build with its JSON pointer and step name. A
package can generate route fragments at build time, and a host names them with an `include`
step, so Nix never reads the generated file.

The module's options for features beyond virtual hosts are `metrics.*` (a `_metrics` site on its
own listener, whose port the module passes to `check --expect-tcp` and keeps out of the
firewall unless `metrics.openFirewall`), `kubernetes.*` (the package with the feature, and the
kubeconfig as a systemd credential), `trustedProxies`, and per host `tls.acme` with the
top-level `acme.stateDirectory` (in-process ACME instead of a `security.acme` certificate, with
the unit's `StateDirectory`). A host sets one certificate source: `acme`, `acmeCert`, or
`certFile` with `keyFile`. Load balancing, health and limits are keys of the route steps and
need no option.

The flake is built from these files:

- `flake.nix` lists the inputs and imports the files below.
- `nix/toolchain.nix` pins Rust through `rust-toolchain.toml` with fenix.
- `nix/package.nix` builds the package with crane and defines the test, clippy and rustfmt
  checks.
- `nix/shell.nix` is the dev shell.
- `nix/module.nix` is the NixOS module.
- `nix/examples/` holds example hosts and the checks that evaluate the module for them.

`checks.<system>.module-eval` evaluates each example host without building anything. It
compares the certificates, groups, unit, firewall, the ports given to `check` and the kernel
modules the module derives with expected values, and the emitted config with
`tests/fixtures/config/<host>.json`. It also evaluates single options (the metrics site and its
ports, the Kubernetes credential, in-process ACME, trusted proxies) and the assertions that
reject conflicting settings. After you
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
`tests/fixtures/site/upstreamer`, where `@out@` stands for the site package's store path. It
holds twenty mistakes that give the same diagnostics from JSON and from TOML, and the positions
TOML diagnostics must name. Compiling every fixture written as TOML to a plan equal to the JSON
one is a unit test in `src/plan/load.rs`. `tests/cli.rs` covers the command line: exit codes,
`.toml` files, `example` and `convert`.
