# Trusted proxies

Behind a CDN or a load balancer, every TCP connection comes from the CDN. Without help,
`{remote_host}` is the CDN's address, an access log lists the CDN for every request, and a rate
limit or a hash key treats all your visitors as one client.

`trustedProxies` tells upstreamer which peers may say who the client is, and where they say it.
For a request from one of those peers the client address becomes the address in the header you
name. For every other peer the headers are ignored, because anyone can write them.

```json
{
  "version": 1,
  "trustedProxies": { "from": ["cloudflare"], "header": "CF-Connecting-IP" },
  "sites": [ ... ]
}
```

```toml
trustedProxies = { from = ["cloudflare", "10.0.0.0/8"], header = "CF-Connecting-IP" }
```

## Settings

`from` lists the peers that are trusted. Each entry is one of:

- a CIDR range: `10.0.0.0/8`, `2001:db8::/32`;
- a single address: `192.0.2.7`, which means `/32` (or `/128`);
- `cloudflare`, the ranges Cloudflare publishes (see below).

Ranges are written as their network address: `10.0.0.1/8` is rejected with the spelling to use
(`10.0.0.0/8`), because a stray host bit usually means a typo. An empty list is rejected too.
`0.0.0.0/0` and `::/0` are accepted with a warning: they trust every peer, so any client can
choose the address upstreamer believes.

`header` is the field that holds the client address. The name is case-insensitive.

| header | what upstreamer reads |
|---|---|
| `CF-Connecting-IP` | one address. Cloudflare sets it on every request. |
| `X-Real-IP` | one address, as nginx and many load balancers set it. |
| `X-Forwarded-For` | a list. The client is its rightmost address that is not a trusted proxy. |

## What changes for a trusted peer

The client address is what these see:

- `{remote_host}`, and `{remote_net}` (the address's /64 for IPv6);
- the `remote_ip` field of the access log;
- the key of a `limit` step and of a `hash` balance policy, when it is `{remote_host}` or
  `{remote_net}` or a template that uses them.

`{peer_host}` is always the address of the connection's peer, trusted or not.

The `X-Forwarded-For` header upstreamer sends to an origin is rewritten to match:

| peer | `X-Forwarded-For` sent to the origin |
|---|---|
| trusted, and its header gave the client | the chain the peer sent, then the peer: `198.51.100.23, 10.1.1.1, 203.0.113.9` |
| trusted, but no usable address in its header | the peer alone |
| untrusted | the peer alone, so a client cannot plant addresses an origin might believe |
| (no `trustedProxies` set) | `{remote_host}`, the peer, as before |

An origin that wants the real client reads the rightmost address of the chain that is not its
own proxy, or uses the `X-Real-IP` you set: a proxy step's `headers` can add
`"X-Real-IP": "{remote_host}"`.

## What counts as an address

An entry is an IPv4 or IPv6 address as written by a proxy: `192.0.2.1`, `2001:db8::1`, and the
forms that carry a port (`192.0.2.1:443`, `[2001:db8::1]:443`, `[2001:db8::1]`). An
IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) is the IPv4 address it maps, both when it names a
client and when a dual-stack listener reports an IPv4 peer. Everything else is not an address:
`unknown`, an obfuscated token like `_hidden`, an interface zone (`fe80::1%eth0`), an address
with a leading zero (`010.0.0.1`), an empty value.

When the value cannot be read, the peer stays the client. Upstreamer never replaces a value it
cannot read with a guess:

- `CF-Connecting-IP` and `X-Real-IP` must appear once and hold one address. Two fields or a
  list are ambiguous, so they are ignored.
- In an `X-Forwarded-For` chain (several fields count as one chain, in order), an entry that is
  not an address ends the part that can be trusted. Entries to its left are never reached, so
  `198.51.100.23, unknown` gives the peer, not `198.51.100.23`. Unreadable entries to the left
  of a readable untrusted address do not matter: `unknown, 198.51.100.23` gives
  `198.51.100.23`. Empty entries (`a,,b`) are ignored.
- When every address in the chain is itself a trusted proxy, the leftmost one is the client:
  the request started inside your trusted network.

## Why the rightmost

Each trusted proxy appends the address it received a connection from. Everything left of the
first untrusted address in the chain was written by that untrusted party, or by someone it
forwarded for, and can be anything. Reading from the left, as a naive `split(",")[0]` does, lets
a client choose its own address by sending `X-Forwarded-For: 1.2.3.4`.

Reading from the right is only safe while `from` lists every proxy between the client and
upstreamer, and no more. A proxy missing from the list makes its address the client. An
address in the list that is not a proxy lets whoever holds it skip past as "trusted".

## The Cloudflare preset

`cloudflare` expands to the IPv4 and IPv6 ranges published at
<https://www.cloudflare.com/ips/>. The list lives in `src/trust/cloudflare.rs`, which
`scripts/cloudflare-ranges` writes from Cloudflare's published lists:

```sh
scripts/cloudflare-ranges           # rewrite the file
scripts/cloudflare-ranges --check   # exit 1 when it is out of date (for CI)
```

Cloudflare rarely changes the list. Regenerate it, review the diff and commit it before a
release. The ranges are part of the binary, so a running proxy keeps the list it was built with:
upgrade it, or write the ranges in `from` yourself, to follow a change sooner.

Put the proxy behind Cloudflare only: a peer that reaches upstreamer without passing through
Cloudflare is not in the list, so its `CF-Connecting-IP` is ignored, which is the point. But if
your origin port is open to the internet, anyone can connect directly, and the client they
present is their own address. Close the port to everyone but Cloudflare (a firewall rule on the
same ranges, or Cloudflare Tunnel) if you need that guarantee for anything but logs.

## Cost

A plan without `trustedProxies` has no trust step. The request path does not test for it.

With it, every request makes one lookup of the peer in the trusted set (a binary search over a
few merged ranges, 3 to 5 ns), and a request from a trusted peer reads one header. Nothing
allocates per request; the ranges are sorted and merged once, when the config is compiled.
Measured on an Apple M6 with a release build, over a head with five common headers:

| request | per request |
|---|---|
| untrusted peer | 3.6 ns |
| trusted peer, `CF-Connecting-IP` | 18 ns (IPv6: 26 ns) |
| trusted peer, `X-Forwarded-For` with three entries | 53 ns |
| the `X-Forwarded-For` sent to the origin | 33 ns |

`cargo test --release --lib trust::tests::cost -- --ignored --nocapture` reproduces them.

## Not supported

- The `Forwarded` header (RFC 7239) and the PROXY protocol. A connection that carries a PROXY
  header is not understood.
- A header chosen freely. The three above are the ones CDNs and load balancers set; ask for
  another if you run one that does not.
- Named presets other than `cloudflare`: write the ranges.
- A trusted peer on one listener and not another. The setting is for the whole config.
