# Fuzz targets

cargo-fuzz targets for every place upstreamer reads bytes it does not control: what clients
send, and what the servers it calls (origins, an ACME CA, the Kubernetes API) answer. Each
target checks invariants, not only the absence of a panic, and runs under AddressSanitizer.

The targets call into the crate through its `internals` feature (`upstreamer::codec`,
`upstreamer::h2`, `upstreamer::fuzz`), which is not part of its API.

## Targets

| target | input | what must hold |
|---|---|---|
| `request` | an HTTP/1.1 request head | an accepted head is forwarded as bytes that parse back to the same request |
| `response` | an origin's HTTP/1.1 response head | an accepted head is relayed as bytes that parse back to the same response |
| `chunked` | a chunked body | scanning agrees whole and split at any point, decoding agrees with scanning, decoded data re-encoded decodes the same |
| `h1_conn` | the bytes of a client on an HTTP/1.1 connection: pipelined requests, bodies, `Expect`, upgrades | the connection ends, and the client reads a response per request in order, each well framed, nothing after one that closes |
| `h2_frames` | a client's HTTP/2 frames into the protocol engine | no panic, bounded output, whole frames, response blocks that decode in step with the encoder, windows within RFC 9113's bounds, streams within the limit, request bodies held within the windows |
| `h2_hpack` | an HPACK field block | what decodes survives the encoder and a second decoder; output bounded by the input |
| `h2_conn` | a client's HTTP/2 frames through the connection driver | the connection ends, frames are whole, blocks decode, HEADERS and DATA only on streams the client opened, DATA within the windows the client granted |
| `files` | a request target and conditional and range headers, against a real tree with files beside its root | a clean path stays clean and cleans to itself again, nothing outside the root is served, ranges lie within their file, a stripped prefix leaves an upstream target that names the path the routes saw |
| `trust` | `CF-Connecting-IP`, `X-Real-IP` and `X-Forwarded-For` values from trusted and untrusted peers | only a trusted peer names the client, the client is an address its header holds (the rightmost untrusted one of a chain), the chain sent upstream ends with the peer |
| `route` | a request through the fleet's configs and `tests/fixtures/fuzz/route.json` | a clean path, header fields without control bytes after every template edit, an upstream target that names the routed path, an upstream head that parses back whole, keys that hash consistently |
| `acme` | a CA's response, read to close | bodies framed by length or by chunks read back the same, every URL the client would follow parses back to itself |
| `kube` | an API server's list or watch response, cut into reads of any size | one byte at a time, any size or all at once give the same lines, endpoints and failure |

`h1_conn` and `h2_conn` serve one connection per input with the real drivers on one end of a
Unix socket pair, behind routes that answer from memory, from files, with compression, by
redirect and error route, and through an origin running in the same process. Tokio's clock
is paused, so every timeout passes at once, and a connection still open after an hour of
that clock fails the input.

`http.dict` and `h2.dict` are libFuzzer dictionaries for the HTTP/1.1 and HTTP/2 targets.

## Running

The targets need a nightly compiler; the flake's `fuzz` shell has one and cargo-fuzz:

```sh
nix develop .#fuzz
cd fuzz
cargo fuzz list
cargo fuzz run h1_conn corpus/h1_conn seeds/h1_conn -- -dict=http.dict -max_total_time=600
```

The first directory is the working corpus, where libFuzzer adds what it finds (`corpus/` is
not committed); `seeds/<target>` is the committed starting corpus, read but never written.
Useful libFuzzer options: `-max_total_time=<s>`, `-jobs=<n> -workers=<n>`, `-timeout=20`,
`-rss_limit_mb=4096`, `-max_len=65536`.

## A crash

libFuzzer writes the input to `artifacts/<target>/crash-<sha1>` (or `timeout-`, `oom-`).

```sh
cargo fuzz run h1_conn artifacts/h1_conn/crash-<sha1>       # reproduce it
cargo fuzz tmin h1_conn artifacts/h1_conn/crash-<sha1>      # minimize it
cargo fuzz fmt h1_conn artifacts/h1_conn/minimized-from-<sha1>  # print it
```

Fix it with a unit test in the crate that reproduces the input as a plain test, and add the
input to `seeds/<target>` so every later run starts from it.

## Corpora

```sh
cargo fuzz cmin h1_conn corpus/h1_conn       # minimize the working corpus in place
# Refresh the committed seeds: the smallest set covering both.
mkdir new && cargo fuzz run h1_conn new seeds/h1_conn corpus/h1_conn -- -merge=1
```

Keep `seeds/` minimized: the whole of it stays well under a few megabytes.

## CI

`.github/workflows/fuzz.yml` builds every target. On a pull request it runs each for a
minute from `seeds/`; once a day it runs each for 15 minutes from the corpus earlier daily
runs kept in the actions cache, minimizes that corpus and keeps it. A crash fails the run and
its input is uploaded as an artifact.
