# Configuration reference

upstreamer reads one config file: JSON or TOML, by the file's extension (`.toml` is TOML,
anything else is JSON). Both are the same schema. The NixOS module writes it as JSON from Nix
options, and this page is the reference for everyone who writes it by hand. The schema is
strict: a misspelt key is an error, never ignored, and `upstreamer check` reports every mistake
with the JSON pointer of the value, the site and step it is in, and for TOML the line and
column.

- [A first config](#a-first-config)
- [How a request is answered](#how-a-request-is-answered)
- [Top level](#top-level)
- [Sites](#sites)
- [Steps and matchers](#steps-and-matchers)
- [Templates](#templates)
- [Actions](#actions)
- [Proxying, balancing and health](#proxying-balancing-and-health)
- [Rate limits](#rate-limits)
- [Metrics](#metrics)
- [Kubernetes](#kubernetes)
- [Trusted proxies](#trusted-proxies)
- [Certificates](#certificates)
- [Value formats](#value-formats)
- [TOML](#toml)
- [Commands](#commands)
- [Running it](#running-it)

## A first config

```sh
upstreamer example > upstreamer.toml      # a commented config to start from
upstreamer check --config upstreamer.toml
upstreamer run --config upstreamer.toml
```

```toml
version = 1
listen.http = ["0.0.0.0:8080"]

[[sites]]
name = "app"
hosts = ["*"]
routes = [{ proxy = "http://127.0.0.1:3000" }]
```

`upstreamer example --list` names the other examples: HTTPS with certificates upstreamer issues
itself, load balancing with health checks, a rate-limited API, metrics, the client address
behind Cloudflare, and Kubernetes discovery. They live in
[`examples/`](../examples) and `check` passes on each of them.

## How a request is answered

A config is a list of **sites**. A site names the **hosts** it answers, where it listens, and
whether it serves HTTPS. A request goes to the site whose host matches its `Host` header (or
its server name, over HTTP/3), then runs the site's **routes**: an ordered list of
**steps**. Each step has an optional `when` matcher and one action. A step whose `when`
does not hold is skipped. Some actions change the request or the pending response and let the
next step run (`set`, `rewrite`, `headers`, `limit`, ...); others answer and end the routing
(`proxy`, `files`, `respond`, `redirect`, `error`, `metrics`). A request that reaches the end
of the routes without an answer gets 404.

When an answer is an error (an `error` step, a missing file, no origin to reach), the site's
**errors** run: error routes tried in order, the first whose `status` list holds the code
running its own steps, so an error page is an ordinary route.

Everything about a feature is a property of a step. A feature no step names costs nothing: a
config without a `limit` step does no rate limiting work, one without `metrics` counts nothing,
and a proxy step with one origin and no `balance`, `retries`, `failStatuses` or `health` takes
the direct path.

## Top level

| key | default | meaning |
|---|---|---|
| `version` | required | `1` |
| `workers` | one per CPU the process may run on | worker threads, each pinned to a CPU. `upstreamer run --workers N` overrides it |
| `listen.http` | `["0.0.0.0:80", "[::]:80"]` | addresses of plain HTTP sites and of the HTTP to HTTPS redirect |
| `listen.https` | `["0.0.0.0:443", "[::]:443"]` | addresses of TLS sites: HTTPS on TCP, and HTTP/3 on the same UDP ports |
| `http3` | `true` | serve HTTP/3 on every `https` address, for sites that do not turn it off |
| `timeouts` | see below | server-side timeouts |
| `limits` | see below | request size limits |
| `trustedProxies` | none | peers that may report the client's address, see [Trusted proxies](#trusted-proxies) |
| `acme` | none | settings shared by sites that get their certificate from in-process ACME, see [Certificates](#certificates) |
| `sites` | required | the list of sites |

Each of `listen.http` and `listen.https` has its own default, so `listen.http = [...]` alone is
valid. The wildcard defaults bind `[::]` as IPv6-only, so startup never waits for an interface
to have an address.

`timeouts`:

| key | default | meaning |
|---|---|---|
| `header` | `10s` | from the first byte of a request to the end of its head (the slowloris bound) |
| `keepAlive` | `75s` | how long a connection with no request in flight stays open: between requests on HTTP/1.1, without streams on HTTP/2, without packets on HTTP/3. Also how long a proxied request body may send nothing before the request fails with 502 |
| `shutdown` | `10s` | after SIGTERM, how long requests in flight and open tunnels may run before they are cut |

`limits`:

| key | default | meaning |
|---|---|---|
| `maxHeadBytes` | 32 KiB | the largest request head |
| `maxHeaderFields` | 100 | the most header fields in a request (at most 256) |
| `maxStreams` | 128 | requests a client may have open at once on one HTTP/2 or HTTP/3 connection |

## Sites

```toml
[[sites]]
name = "shop"
hosts = ["shop.example.com", "www.shop.example.com"]
tls = { cert = "/etc/ssl/shop/fullchain.pem", key = "/etc/ssl/shop/key.pem" }
headers = { Server = false, X-Frame-Options = "DENY" }
accessLog = "/var/log/upstreamer/shop.log"
routes = [...]
errors = [...]
```

| key | default | meaning |
|---|---|---|
| `name` | required | names the site in diagnostics, logs and the `site` label of metrics |
| `hosts` | required | exact names, `*.suffix` wildcards, or `*` (any host). Matched case-insensitively, without the port |
| `tls` | none | present: serve HTTPS. Absent: plain HTTP on `listen.http` |
| `listen` | the defaults | addresses of this site, instead of `listen.http` (plain) or `listen.https` (TLS). A TLS site with its own `listen` gets no HTTP redirect |
| `headers` | none | response headers set (a string, a [template](#templates)) or removed (`false`) on every response of the site, error responses and redirects included, before any step's `headers` |
| `routes` | none | the steps |
| `errors` | none | the error routes |
| `accessLog` | none | an absolute path; see below |

Two sites may not answer the same host on the same listener, and a plain site and a TLS
site's HTTPS redirect may not share a host either: `check` names both sites.

### `tls`

| key | default | meaning |
|---|---|---|
| `cert`, `key` | | PEM files: the certificate chain and its private key. Both, or `acme`, not both |
| `acme` | | `{ email, directory?, challenge? }`: the certificate is issued and renewed by this process, see [Certificates](#certificates) |
| `redirectHttp` | `true` | answer plain HTTP requests for the site's hosts, on `listen.http`, with a 308 redirect to HTTPS. Only for sites on the default addresses |
| `http3` | the top-level `http3` | serve HTTP/3 beside HTTPS and advertise it with `Alt-Svc` |

A certificate file that is missing, unreadable or that does not match its key does not fail the
config. The site's names keep the certificate they had, or get a self-signed one for each name,
until a reload finds a usable pair. A new host therefore never stops the others from serving,
and a reload re-reads every pair, so replacing a file and reloading renews a certificate.

### `accessLog`

One JSON object per line for every request the site answers, and for every WebSocket or other
upgraded connection once it closes: `ts` (UTC, RFC 3339, milliseconds), `remote_ip`,
`remote_port`, `host`, `method`, `target` (as the client sent it), `proto`, `user_agent`,
`referer`, `status`, `bytes`, `duration` (seconds), `upstream` (the `host:port` of the last
`proxy` step that ran, or `null`). Sites naming one path share one file. Each worker buffers
lines and appends them in batches, at the latest a second after the request ends, so a full
disk drops lines (counted in the journal) and never slows a request. A reload reopens the files,
which is how log rotation starts a new one.

## Steps and matchers

A step is `{ name?, when?, <one action> }`. A step with two actions, with none, or with an
unknown key is an error at its own position. `name` appears in diagnostics (`shop/cart`) and as
the `route` label of [metrics](#metrics).

`when` is a matcher: a set of tests that must **all** hold.

| key | holds when |
|---|---|
| `path` | the clean, decoded path matches one of the patterns (a string or a list): exact (`/blog`), prefix (`/api/*` matches everything under `/api/`), suffix (`*.etag`), or a glob with `*` inside. `*` matches any run of characters, `/` included. Letters compare ASCII case-insensitively |
| `pathRegex` | the path matches the regex. Its capture groups are `{re.N}` in this step's action |
| `method` | the method is one of those listed (a string or a list) |
| `header` | for each `{ Name = pattern or list }`: some value of the field, with the values joined by `, `, matches a glob. An absent field never matches |
| `headerRegex` | the same with a regex |
| `query` | for each `{ key = value or list }`: some value of the query argument (percent-decoded) equals one of the values |
| `value` with `in` or `regex` | the [template](#templates) `value` expands to one of the strings in `in`, or matches `regex` |
| `file` | `{ root, paths }`: one of `paths` (templates) names a regular file under `root`. A trailing `/` asks for a directory |
| `after` | the clock has passed this instant: unix seconds, or an RFC 3339 time with an offset (`2026-12-01T00:00:00Z`). A scheduled release |
| `all`, `any`, `none` | every one, at least one, or none of the listed matchers holds. They take lists, so merging Nix attribute sets cannot silently change a negation |

A step with several regexes in its `when` cannot say which one `{re.N}` means; `check` says so.

## Templates

Strings in `rewrite`, `redirect.to`, `respond.body`, `set`, `headers`, `requestHeaders`, a
proxy's `headers` and the `key` of a `limit` or a `hash` balance are templates. `{name}`
expands to a value of the request; `{{` and `}}` are literal braces. An unknown name is an
error found by `check`.

| placeholder | expands to |
|---|---|
| `{host}` | the host, lowercase, without the port |
| `{remote_host}` | the client's address: the peer's, or the one a [trusted proxy](#trusted-proxies) forwarded |
| `{remote_net}` | the client's IPv4 address, or its IPv6 /64 as `2001:db8:1:2::/64` |
| `{peer_host}` | the address of the connection's peer, always |
| `{remote_port}`, `{scheme}`, `{method}` | as named |
| `{path}`, `{query}`, `{?query}` | the clean path; the query; empty, or `?` and the query |
| `{uri}` | the request-target as it would go upstream |
| `{query.K}`, `{cookie.K}`, `{header.Name}` | an argument, a cookie, or a header field (values joined by `, `) |
| `{vars.k}` | a variable assigned by `set` |
| `{re.N}` | group N of the regex in the same step's `when` |
| `{err.status_code}`, `{err.status_text}` | the status being handled, inside an error route |
| `{err.retry_after}` | inside an error route, the seconds until a refused request may retry (a rate limit, or a pool with no origin up); empty otherwise |

`{vars.x}` read before any `set` assigns it expands to nothing, and `check` warns. A key (for
`limit` and `balance.hash`) is computed from the request alone, so it may not read `{re.N}`,
`{err.*}`.

## Actions

Non-terminal, in the order they take effect:

| action | value | effect |
|---|---|---|
| `set` | `{ name = template, ... }` | assigns variables. All templates of one `set` see the variables as they were before it |
| `rewrite` | template | replaces the path (and the query, when the template contains a `?`). Starts with `/` |
| `stripPrefix` | literal path | removes the prefix from the path and from the target sent upstream |
| `tryFiles` | `{ root, paths }` | rewrites the path to the first of `paths` that exists under `root`. No change if none |
| `headers` | `{ Name = template or false }` | response header edits, applied after the handler wrote its headers |
| `requestHeaders` | `{ Name = template or false }` | request header edits, before the handler runs |
| `encode` | list of `br`, `zstd`, `gzip` | encodings a response may be compressed with, in preference order |
| `routes` | list of steps | runs the steps in order |
| `firstOf` | list of steps | runs only the first step whose `when` holds |
| `include` | absolute path | splices the steps of a [fragment](#fragments) here |
| `limit` | see [Rate limits](#rate-limits) | takes a token, or answers 429 |

Terminal:

| action | value | effect |
|---|---|---|
| `proxy` | URL, or an object | forwards to an origin, see [Proxying](#proxying-balancing-and-health) |
| `files` | `{ root, precompressed?, etagSidecar?, index? }` | serves files, see below |
| `respond` | `{ status?, body? }` | answers with this status (200 to 599; default 200, or the error's status inside an error route) and body (a template) |
| `redirect` | `{ to, status }` | redirects. `status` is 301, 302, 303, 307 or 308; `to` is a template |
| `error` | status 400 to 599 | answers an error through the site's error routes |
| `metrics` | `{}` | answers with the Prometheus exposition, see [Metrics](#metrics) |

Header names may not be framing or hop-by-hop headers (`Content-Length`, `Transfer-Encoding`,
`Connection`, ...): the protocol layer writes those. Header edits set a field with a string and
remove it with `false`. JSON also accepts `null` for removal; TOML has no `null`.

`files`:

| key | default | meaning |
|---|---|---|
| `root` | required | the directory served. The request path is cleaned (decoded, no `.` or `..`) before it is joined to it, so a request cannot leave the root |
| `precompressed` | none | sidecars tried in this order when the client accepts the encoding: `br` serves `<file>.br`, `zstd` `<file>.zst`, `gzip` `<file>.gz` |
| `etagSidecar` | none | an extension such as `.etag`: the content of `<file>.etag` is the file's ETag |
| `index` | `["index.html"]` | names tried for a directory |

Conditional requests, ranges and content types are handled; a large file is sent with
`sendfile`, over kernel TLS where the kernel offers it.

### Error routes

```toml
[[sites.errors]]
status = [502, 503, 504]          # absent: every error
routes = [
  { headers = { Cache-Control = "no-store" } },
  { respond = { body = "Try again in a minute.\n" } },
]
```

A response produced there keeps the error's status unless it names another. `limit` is not
allowed inside an error route.

### Fragments

`include` names a JSON or TOML file (by extension) of the form
`{ "fragment": 1, "routes": [...], "headers": {...}, "errors": [...] }`. Its headers join the
including site's (the same name in both is an error) and its errors are appended to the site's.
A package can generate fragments at build time; `upstreamer check --fragment <file>` validates
one as if a site included it.

## Proxying, balancing and health

```toml
proxy = "http://127.0.0.1:3000"                      # one origin
proxy.to = ["http://10.0.0.1:3000", "http://10.0.0.2:3000"]   # several
```

`proxy` is a URL (`http://host:port`, or `https://host:port` to speak TLS to the origin), or an
object:

| key | default | meaning |
|---|---|---|
| `to` | required | one origin URL, a list of origins (each a URL or `{ url, weight }`), or a discovery source (`{ kubernetes = {...} }`) |
| `balance` | `"roundRobin"` | how a request picks an origin, see below. Ignored for a single origin |
| `retries` | `1` when the target can hold several origins, else `0` | further attempts, on other origins, of a request that may be replayed after a failed attempt |
| `failStatuses` | none | origin statuses that count as a failed attempt |
| `health` | see below | `passive` and `active` health checks |
| `tlsSkipVerify` | `false` | do not verify the origin's certificate |
| `headers` | see below | request header edits for the origin |
| `timeouts` | see below | `dial`, `responseHeader`, `idle`, `tunnelIdle` |

The client's `Host` passes through. The proxy sets `X-Forwarded-For` (`{remote_host}`; behind
[trusted proxies](#trusted-proxies), the chain the trusted peer sent, then the peer),
`X-Forwarded-Proto` and `X-Forwarded-Host`, unless `headers` names the field. WebSocket and other
upgrades, streamed bodies and server-sent events pass through.

`timeouts`:

| key | default | meaning |
|---|---|---|
| `dial` | `5s` | connecting to the origin |
| `responseHeader` | none | from the end of the request head to the end of the response head |
| `idle` | `2m` | how long a pooled idle connection to the origin lives. It belongs to the origin: two steps that proxy to one origin with different values are an error |
| `tunnelIdle` | none | an upgraded connection that carried nothing either way this long is closed |

### Weights and policies

A member is a URL or `{ url = "...", weight = 2 }` (weight 1 by default): an origin of weight 2
takes twice the share. A weight is at most 1000, and 0 takes the origin out of rotation while it
stays in the config; at least one member must weigh more than 0. An origin listed twice in one
`to` is an error, even when the two URLs differ only in case or a trailing `/`: give it one entry
with a weight. `balance` is one of:

| policy | picks |
|---|---|
| `"roundRobin"` | the members in turn, by weight |
| `"leastRequests"` | the member with the fewest requests in flight on this worker, ties broken round robin |
| `"p2c"` | two random members, the one with fewer requests in flight on this worker |
| `{ hash = "<template>" }` | by consistent (Maglev) hashing of the expanded template, such as `"{cookie.cart_session}"`: the same key reaches the same origin while it is healthy, and adding or removing an origin moves only that origin's share. An empty expansion falls back to round robin |

A hash key is hashed with a fixed seed, so it picks the same origin on every worker, across
restarts, and on every replica with the same members. When the origin a key lands on is out
(failing its probe, ejected, or already tried by this request), seven more slots derived from the
key are tried, and then the request falls back to round robin, not to the origin of some other
key. The key cannot read `{re.N}` or `{err.*}`.

The Maglev table has the smallest prime number of slots at or above 100 per member rounded up to
a power of two, at least 2048 and at most 65537: 2053 slots for up to 20 members, 4099 for up to
40, and so on. The size changes only when the member count crosses one of those powers of two, so
adding or removing a member within a band moves only the keys that Maglev has to move; crossing a
band reshuffles every key once.

In-flight counts are per worker, which is what a thread-per-core proxy can read without sharing
memory. A request that cannot be replayed is never retried.

### Retries and failure

An attempt fails when the connection is refused, times out or resets before the response head,
when the head is malformed, or when the origin answers a status in `failStatuses`. A failed
attempt moves to another origin, up to `retries` more times, only when the request can be sent
again unchanged: its method is idempotent (`GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `TRACE`)
and none of its body has been read, which holds for any request without a body. Bodies are never
buffered to make a request replayable, so a `POST`, or a request whose body has started
upstream, gets the answer of its first attempt. A retry prefers an origin this request has not
tried; a pool whose every origin has been tried reuses one, on a fresh connection. Apart from
`retries`, a pooled connection that the origin closed while idle is retried once on a freshly
dialled one, for the same requests, with or without a pool.

When the last attempt gets a `failStatuses` response, that response, its body included, is
passed to the client: the origin's own error page beats one made up here. When the last attempt
failed otherwise, the answer is 502 (refused or reset) or 504 (timed out). When no origin can be
picked at all (every member fails its probe or weighs 0, or a discovery source has not reported
yet), the answer is 503 with `Retry-After`, through the site's error routes
(`{err.retry_after}` is the same number): the seconds until the first member could be back,
which is its remaining ejection or one probe interval, and 1 for a pool with no member yet.

### Health

`health.passive` ejects an origin that fails in a row; it is on by default for a target with
several origins:

| key | default | meaning |
|---|---|---|
| `maxFails` | `3` | consecutive failed attempts on one worker that eject the origin from every worker. `0` turns passive checks off |
| `cooldown` | `10s` | how long an ejection lasts. It doubles for each ejection in a row, up to 8x |

`health.active` probes the origin with a `GET`:

| key | default | meaning |
|---|---|---|
| `path` | required | the request path, with its query if any |
| `host` | see below | the `Host` header of the probe |
| `interval` | `10s` | between probes, jittered by up to 10% |
| `timeout` | `2s` | dial, TLS and response head together |
| `expect` | any 2xx or 3xx | statuses that pass |
| `healthyAfter` | `2` | consecutive passes that bring a failing origin back |
| `unhealthyAfter` | `3` | consecutive failures that take an origin out |

Without `host`, a probe of an origin from a URL sends the URL's host, with its port unless it is
the scheme's default and in brackets for IPv6 (`10.0.0.1:8080`, `storage.lan`, `[::1]`). A probe
of a Kubernetes source sends its `serverName` when it has one, else `<service>.<namespace>.svc`;
a source chosen by `selector` names no single host, so it must set `host`.

A probe belongs to the origin, not to a step: two steps that probe one origin differently are
an error, as two idle timeouts are. When every origin that passes its probes is also ejected by
passive checks, they are all eligible again; refusing everything on a correlated blip would turn
it into an outage. An origin that fails its probes stays out.

Detection is per worker: an origin is ejected after `maxFails` failures counted on one worker,
which with traffic spread over several workers can take more failures in all, and a success
writes no shared memory.

## Rate limits

```toml
[[sites.routes]]
name = "login"
when = { path = "/v1/login", method = "POST" }
limit = { rate = "5/m", burst = 5 }
```

A `limit` step applies to the requests its `when` matches, at its place in the list. It takes one
token from the bucket of the request's key. When the bucket is empty, the request is answered
429 with `Retry-After`, through the site's error routes.

| key | default | meaning |
|---|---|---|
| `rate` | required | `<count>/s`, `<count>/m` or `<count>/h` |
| `burst` | the rate per second, rounded up, at least 1 | requests a key may make at once after being idle |
| `key` | `"{remote_net}"` | a [template](#templates); each distinct expansion has its own bucket. A constant such as `"all"` is one bucket for every request the step sees |
| `keys` | `65536` | buckets kept, 8 bytes each. When every bucket near a new key is in use, the least-limited one is replaced |

The limit is exact across workers: a client gets its rate however many connections it opens and
whichever worker serves them. Two keys that land on the same bucket and share a 24-bit
fingerprint share it, about 5 in 10 million new keys. Buckets survive a reload when the step's
site, position, key and size are unchanged, and are lost on restart. Limits are not shared
between proxy instances.

`check` warns about a constant-key `limit` with no `when` (on the step or a block around it)
that comes before a `metrics` step of the same site: every scrape would take a token from the
bucket the rest of the traffic drains, and be refused with it.

## Metrics

A `metrics` step answers with the Prometheus text exposition (format 0.0.4), so the endpoint is
an ordinary site: put it on a loopback listener, or guard it with a `when`.

```toml
[[sites]]
name = "metrics"
hosts = ["*"]
listen = ["127.0.0.1:9100", "[::1]:9100"]
routes = [{ when.path = "/metrics", metrics = {} }]
```

Collection runs only while some site has a `metrics` step. `check` warns when a `metrics` step
without a `when` is reachable on a non-loopback address.

| family | type | labels |
|---|---|---|
| `upstreamer_requests_total` | counter | `site`, `route`, `code` (`2xx`...) |
| `upstreamer_request_duration_seconds` | histogram | `site`, `route` |
| `upstreamer_upstream_responses_total` | counter | `origin`, `code` |
| `upstreamer_upstream_failures_total` | counter | `origin`, `cause` (`connect`, `timeout`, `status`, `reset`, `tls`) |
| `upstreamer_upstream_response_seconds` | histogram | `origin` |
| `upstreamer_upstream_healthy` | gauge | `origin` (0 or 1; a count for a discovery source) |
| `upstreamer_upstream_retries_total` | counter | `origin` |
| `upstreamer_ratelimit_rejected_total` | counter | `site`, `route` |
| `upstreamer_ratelimit_evictions_total` | counter | `site`, `route` |
| `upstreamer_connections_open`, `upstreamer_connections_total` | gauge, counter | `listener` |
| `upstreamer_tls_handshakes_total` | counter | `listener`, `result` (`full`, `resumed`, `failed`) |
| `upstreamer_discovery_endpoints`, `upstreamer_discovery_synced` | gauge | `source` |
| `upstreamer_config_generation` | gauge | |
| `upstreamer_config_reloads_total` | counter | `result` (`ok`, `rejected`) |
| `upstreamer_build_info` | gauge | `version`, `features` |
| `process_cpu_seconds_total`, `process_resident_memory_bytes`, `process_open_fds`, `process_max_fds`, `process_start_time_seconds`, `process_threads` | | the standard process metrics |

The `route` label is the nearest enclosing step with a `name`; unnamed steps share `route=""`,
so name the steps whose traffic you want apart. The number of series is bounded by the config:
sites x named routes x status classes, origins named in the config, limits and listeners.
Origins discovered at run time aggregate under their source, never one series per pod. Counts
lag by up to a second, and survive reloads. `upstreamer check` prints the number of series the
config produces.

## Kubernetes

```toml
[[sites.routes]]
name = "web"
proxy.to.kubernetes = { namespace = "shop", service = "web", port = "http" }
proxy.balance = "p2c"
proxy.health.active = { path = "/readyz", interval = "5s" }
```

`proxy.to.kubernetes` makes the ready endpoints of a Service the members of the pool, by pod
IP, so requests go to pods directly and connections are pooled per worker. It needs a build with
the `kubernetes` cargo feature (the flake's `packages.<system>.kubernetes`); another build fails
`check` and says so.

| key | meaning |
|---|---|
| `namespace` | required |
| `service` or `selector` | exactly one: a Service name, or a label selector (`app=shop`) matching Services whose endpoints are merged into one pool |
| `port` | required: the EndpointSlice port, by name or by number |
| `scheme` | `http` (default) or `https` |
| `serverName` | the SNI and certificate name for `https` members; pod IPs have none of their own |

The client reads EndpointSlices (a list, then a watch that resumes from its version, with a
relist when the server forgets it). It authenticates with the pod's service account when the
process runs in a cluster, or a kubeconfig (`$KUBECONFIG`) holding a bearer token or a client
certificate; `exec` and OIDC plugins are not supported. When the API server is unreachable the
last known endpoints keep serving; before the first list a discovered pool answers 503.
[`docs/kubernetes-rbac.yaml`](kubernetes-rbac.yaml) holds the permissions it needs: `get`,
`list` and `watch` on `endpointslices` in each namespace a source names, nothing else.

## Trusted proxies

```toml
trustedProxies = { from = ["cloudflare", "10.0.0.0/8"], header = "CF-Connecting-IP" }
```

Behind a CDN or a load balancer the TCP peer is the proxy in front, not the client. `from` lists
the peers whose word is believed: CIDR ranges, and `cloudflare` for Cloudflare's published
ranges. `header` is the request header that carries the client's address: `CF-Connecting-IP`,
`X-Real-IP`, or `X-Forwarded-For` (its rightmost address that is not itself a trusted proxy).

For a request from a trusted peer, the address in the header becomes the client's address:
`{remote_host}` and `{remote_net}`, the access log, the metrics, and the keys of `limit` and
`balance.hash` all see it, and the `X-Forwarded-For` sent upstream appends correctly. A request
from any other peer keeps the peer's address, and its header is ignored. The peer stays
available as `{peer_host}`. See [trusted-proxies.md](trusted-proxies.md).

## Certificates

A TLS site's certificate comes from files (`tls.cert` and `tls.key`), from a tool that writes
files (certbot, lego, the NixOS ACME module: a reload re-reads them), or from upstreamer itself:

```toml
acme.stateDirectory = "/var/lib/upstreamer"

[[sites]]
name = "app"
hosts = ["app.example.com", "www.example.com"]
tls.acme = { email = "ops@example.com" }
```

| key | default | meaning |
|---|---|---|
| `tls.acme.email` | required | the contact address of the ACME account |
| `tls.acme.directory` | Let's Encrypt production | the CA's directory URL |
| `tls.acme.challenge` | `"http-01"` | `"http-01"`: the CA fetches a token over plain HTTP on port 80, which the proxy answers before routing. `"tls-alpn-01"`: the CA connects to the HTTPS port and the proxy offers a validation certificate for the `acme-tls/1` protocol |
| `acme.stateDirectory` | `/var/lib/upstreamer` | where the account key and the issued certificates are kept; the process must be able to write it |

The process runs an ACME client (RFC 8555): it creates an account, orders a certificate for the
site's hosts, answers the challenge, and renews at two thirds of the certificate's lifetime with
some jitter, backing off after a failure. Until the first issuance finishes, clients get a
self-signed certificate for the name, and the issued one replaces it without a reload. Wildcard
names and IP addresses cannot be issued this way, and `check` rejects them. See
[acme.md](acme.md).

## Value formats

- **Durations**: an integer and a unit, `ms`, `s`, `m` or `h`: `"300ms"`, `"5s"`, `"2m"`.
- **Rates**: `"<count>/s"`, `"<count>/m"`, `"<count>/h"`.
- **Addresses**: `"host:port"` with an IP, IPv6 in brackets: `"0.0.0.0:80"`, `"[::1]:9100"`.
- **Times** (`after`): unix seconds, or an RFC 3339 time with an offset.
- **Header edits**: a string sets the field, `false` or `null` removes it; `true` is an error.

## TOML

A TOML file is the same schema with another syntax: tables are objects, arrays are arrays.
`upstreamer check` reports the same diagnostics for a TOML file as for the JSON of the same
config, plus the line and column of the value they name.

- TOML has no `null`; write `false` to remove a header.
- An offset date-time is a time: `after = 2026-12-01T00:00:00Z`. A date or time without an
  offset is an error, because the schema has no value for a time without a zone.
- TOML is strict about types: `burst = "5"` is a string where a number is wanted.
- When one table has several mistakes, TOML reports the key that sorts first and JSON the first
  in the file.
- YAML is not offered. Its implicit typing (`no` is a boolean, `010` is eight) would make the
  same text mean different values than the schema reads.

`upstreamer convert <file>` prints a JSON file as TOML, or a TOML file as JSON, for moving a
config over. It converts syntax only; `null` becomes `false` in a header map and is left out
anywhere else.

## Commands

```text
upstreamer run [--config] <file> [--workers N] [--reload-socket PATH]
upstreamer reload --reload-socket PATH
upstreamer check [--config] <file> [--expect-tcp PORT,..] [--expect-udp PORT,..]
upstreamer check --fragment <file>
upstreamer example [NAME | --list]
upstreamer convert <file>
```

`check` compiles the config exactly as `run` does, minus what touches the host: it opens no
socket and no certificate or static root. It reads the includes, so those files must exist. On
success it prints what the config holds and what its features cost:

```text
ok: 3 sites, 14 steps, 3 pools (7 origins, 2 probed), 2 limits (265 KiB), metrics on (212 series)
```

Warnings (an unreachable step, a variable read before it is set, an unguarded public metrics
endpoint) go to stderr and do not fail the check. `--expect-tcp` and `--expect-udp` compare the
ports a firewall opens with the ports the sites listen on, which is how the NixOS module keeps
its firewall and its listeners from drifting.

| exit code | meaning |
|---|---|
| 0 | success |
| 1 | invalid config: diagnostics on stderr, one per line, `file:/json/pointer: site/step: message (line L, column C)` |
| 2 | usage error |
| 3 | runtime failure (a port cannot be bound, a file cannot be read) |

`reload` exits 0 once the running proxy has reloaded, 1 when it tried and kept what it was
serving, and 3 when it could not be asked ([below](#reloading-and-knowing-that-it-worked)).

## Running it

`upstreamer run` serves until SIGTERM or SIGINT, then drains for `timeouts.shutdown`. A reload
reads the config and every certificate file again. A request in flight finishes under the
config it started with, and connections are not dropped. Health, rate-limit buckets of an
unchanged step, and metric counts continue across a reload.

### Reloading, and knowing that it worked

There are two ways to ask for a reload, and they do the same thing:

- `SIGHUP` reloads and tells its sender nothing. What came of it is in the log and, under
  systemd, in the unit's status.
- `upstreamer reload --reload-socket PATH` asks the proxy that runs with the same
  `--reload-socket PATH`, waits until the reload is done, prints the proxy's status line and
  exits 0. When the proxy kept what it was serving, it prints why on stderr and exits 1:

  ```text
  $ upstreamer reload --reload-socket /run/upstreamer/reload
  upstreamer: reload failed, still serving generation 4: /etc/upstreamer/config.json: key must be a string (line 1, column 3)
  ```

  It exits 3 when no proxy answers at the path, or when none answers within 75 s.

The socket is a Unix socket the proxy creates for its own user alone (mode 0600); asking on it
reloads and does nothing else, which a signal from the same user does too. A socket file left
by a proxy that is gone is replaced at the next start.

These outcomes fail a reload, and leave the running generation serving:

- the config cannot be read, parsed or compiled (`upstreamer check` reports the same
  diagnostics beforehand);
- the program file was replaced and the new program does not take over
  ([below](#upgrading-without-a-restart-linux)): it cannot be started, exits, rejects the
  config, cannot sync a discovery source within 10 s, is not ready within 30 s, or is gone
  when the proxy hands over to it.

These do not. The reload succeeds, the proxy serves the new config without the part named,
and the status line `reload` prints and the log say which:

- a certificate or key file that is missing, unreadable or mismatched: its names keep the
  certificate they had, or get a self-signed one;
- an access log file that cannot be opened: its lines are dropped until a reload opens it;
- a new listener whose address cannot be bound: the other listeners serve.

### Upgrading without a restart (Linux)

A reload also looks at the program file: when the file at the path the proxy was started from
is no longer the file it runs (another device or inode), the proxy starts that file and hands
it the listening sockets, instead of reloading. The new process reads the config, takes the
sockets with whatever is queued on them, and becomes the service's main process; the old one
finishes its requests in flight for at most `timeouts.shutdown` and exits. No connection is
refused and no request fails:

- A request on an HTTP/1.1 connection kept from before the upgrade is answered by the old
  process, with `Connection: close`. A connection that stays idle is closed after half of
  `timeouts.shutdown`.
- An HTTP/2 or HTTP/3 connection gets GOAWAY and its open streams finish. A tunnel (WebSocket)
  still open at the deadline is cut, as at a stop. An HTTP/2 request the client sends just as
  the GOAWAY of an idle connection goes out is above the GOAWAY's last stream id: it was not
  processed, and the client may send it again (RFC 9113, section 8.7). Browsers, curl, Go and
  httpx do; Rust's `h2` (under hyper and reqwest) reports it to the application instead.
- HTTP/3: the old process keeps the UDP sockets until its last QUIC connection has ended, and
  the new one answers QUIC from then on. A QUIC handshake begun in between is not answered
  until then; the client's retransmission completes it (about a second later with common
  clients), and a client that races TCP uses HTTP/2 meanwhile.

So replacing the binary at its path (a rename over it, or a changed link) and
`systemctl reload upstreamer` upgrade the proxy. On NixOS a switch to a new package does
exactly that. The program is started with the arguments and the environment of the running
one, inside the same unit, so anything of the unit itself (its user and groups, its sandbox,
its environment) changes only at a restart.

If the new program exits, rejects the config, cannot sync a discovery source within 10 s or is
not ready within 30 s, it is stopped before it took a connection and the reload fails like a
reload of an invalid config: the running process keeps serving, and `upstreamer reload` and
the unit's status say
`reload failed, still serving generation N: cannot hand over to <path>: <reason>`. Every later
reload tries again while the file at the path is still another one, so a reload for a renewed
certificate or a rotated log fails too until the program is replaced by one that runs.

The new process starts fresh, apart from the sockets and the TLS session ticket keys (a
session of the old process resumes on the new one). What a reload keeps and an upgrade does
not: rate-limit buckets start full, origins start in rotation with no failures counted and no
probe results, upstream connections are opened anew, and the metric counters restart from zero
(`process_start_time_seconds` changes with them, as at a restart). Discovered origins are
looked up again, before the new process takes over: it waits until every discovery source has
synced.

Two versions of the program agree on the handover through a small versioned document. A
version that cannot read the running one's document refuses it, which fails the reload as
above; `systemctl restart` upgrades then, with the gap of a restart.

`upstreamer reload` is the new program too, asking the old one. The proxy greets with the
versions of the reload protocol it speaks and `reload` asks in the highest one both speak. When
they share none, `reload` asks nothing and says so. Run by systemd as a unit's `ExecReload=`, it
then exits 0, and systemd sends the SIGHUP of `Type=notify-reload` itself: the reload happens,
and only the unit's status says whether it failed. Run by anything else, it exits 3.

On other systems than Linux, a reload always reloads the config.

Two upgrades in a row are fine: a process that hands over while the one before it still has
QUIC connections passes the wait on, and the last process answers QUIC once all before it
have let go.

### Restarts and crashes under systemd

With `FileDescriptorStoreMax=` in its unit, the proxy keeps its listening sockets in systemd's
file descriptor store. systemd holds them while the unit restarts (`systemctl restart`, a
restart after a crash with `Restart=`) and passes them to the next process, which serves what
queued on them. A connection made while no process ran therefore waits for the next one
instead of being refused. It can wait as long as the stop takes: requests in flight get
`timeouts.shutdown` to finish before the next process starts. A restart still closes the
connections kept open from before it, which an upgrade does not.

`systemctl stop` releases the store and with it the ports. A listener a reload removes leaves
the store too.

A unit for a host without NixOS (the NixOS module generates a hardened one from its options):

```ini
[Unit]
Description=upstreamer
After=network.target

[Service]
Type=notify-reload
ExecStart=/usr/local/bin/upstreamer run --config /etc/upstreamer/config.toml --reload-socket %t/upstreamer/reload
ExecReload=/usr/local/bin/upstreamer reload --reload-socket %t/upstreamer/reload
Restart=on-failure
DynamicUser=yes
RuntimeDirectory=upstreamer
RuntimeDirectoryMode=0700
StateDirectory=upstreamer
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576
FileDescriptorStoreMax=4096
```

Without `DynamicUser`, give the service a user that can read the config and certificates and
write the state directory. Binding ports 80 and 443 needs `CAP_NET_BIND_SERVICE`.
`ExecReload=` is what makes `systemctl reload upstreamer` fail when the reload did: systemd
runs the command, the proxy tells systemd that it reloads and when it is done (`RELOADING=1`,
`READY=1`, and `MAINPID=` when another process took over), and the command's exit status
decides the reload job. The unit stays active either way. Everything that reloads through
systemd gets that result: a deploy, a certificate renewal hook, logrotate's `postrotate`.
With `Type=notify-reload` and no `ExecReload=`, systemd sends SIGHUP and waits for the same
notifications, and a reload that failed counts as done. Keep the type with the command: it is
what lets systemd reload a proxy the command cannot ask. systemd 259 and later run the command
first and signal only a proxy that did not report a reload meanwhile; earlier ones signal as
they start the command, so the proxy reloads twice, and the command's result still decides.
The reload must fit in `TimeoutStartSec` (90 s by default), which the 30 s a new program gets
and the 75 s the command waits do. The default `NotifyAccess=main` and
`KillMode=control-group` are what the upgrade expects.

The NixOS module's unit is this one, hardened. A switch whose reload fails therefore fails
(`switch-to-configuration` names `upstreamer.service` among the failed units and exits
non-zero) while the proxy that ran before serves on, and the module's certificate renewals
fail the same way instead of leaving a renewed certificate unserved without a word.

On NixOS, the module's options write this config for you: [the README](../README.md#nixos) shows
the common ones, and `services.upstreamer.settings` takes any top-level key of this page.
