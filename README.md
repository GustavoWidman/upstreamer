# upstreamer

![rust](https://img.shields.io/badge/rust-2024-orange?logo=rust)
![license](https://img.shields.io/badge/license-MIT-blue)

a reverse proxy and static file server that does the boring parts of caddy, configured with nix options or one small toml file.

it terminates tls, speaks http/1.1, http/2 and http/3, proxies to your apps and serves static files. it runs one thread per cpu, each with its own sockets and connection pools, so nothing is locked on the way through a request. it reloads on `SIGHUP` without dropping a connection, and a config that fails to compile leaves the running one alone. on linux the same signal upgrades it: a new binary at the old path takes the listening sockets over, so no connection is refused and no request fails.

## what it does

- tls with certificates from nixos acme, from files, or issued by upstreamer itself over acme (`http-01` or `tls-alpn-01`). a site whose certificate doesn't exist yet gets a self-signed one until it does, so a new host never delays the others.
- reverse proxying with websockets and other upgrades, streamed bodies and server-sent events.
- load balancing over several origins: round robin, least requests, power of two choices, or consistent hashing of a cookie or header. origins can be weighted, retried on another origin when a request may be replayed, and ejected by passive and active health checks.
- kubernetes service discovery from endpointslices, in the build with the `kubernetes` feature.
- rate limits that are exact across workers: a client gets its rate however many connections it opens, and the answer is a 429 with `Retry-After` that goes through your own error routes.
- a prometheus endpoint, as a route step, so it sits on a loopback listener or behind a matcher like any other site. nothing is counted until a site has one.
- the real client address behind cloudflare or another proxy, for logs, limits and hashing, from a list of trusted peers.
- static files with precompressed sidecars, etag sidecars and conditional requests.
- routes as an ordered list of steps, such as `proxy`, `files`, `rewrite`, `headers` and `redirect`, each with an optional `when` matcher.

a feature no step names is absent from the compiled plan. a config with one origin and no limits does exactly what it did before they existed.

## nixos

```nix
{
  imports = [ upstreamer.nixosModules.default ];

  security.acme = {
    acceptTerms = true;
    defaults = {
      email = "admin@example.com";
      dnsProvider = "cloudflare";
      environmentFile = "/run/secrets/acme.env";
    };
  };

  services.upstreamer = {
    enable = true;
    metrics.enable = true;
    virtualHosts."app.example.com".proxy = "http://127.0.0.1:8080";
    virtualHosts."www.example.com".routes = [
      { when.path = "/api/*"; proxy = "http://127.0.0.1:9000"; }
      { files.root = "/srv/www"; }
    ];
  };
}
```

each virtual host gets tls with an acme certificate named after it unless you say otherwise. certificates come from dns-01 challenges, so the host sets its lego dns provider. the module creates the certificates, opens the firewall, and runs `upstreamer check` on the generated config while the system builds, so a bad route fails the build.

a host that has no dns provider can have the proxy get its own certificate:

```nix
services.upstreamer.virtualHosts."app.example.com" = {
  tls.acme.email = "ops@example.com";
  proxy = "http://127.0.0.1:8080";
};
```

a switch that changes the config or the package reloads the unit and nothing is dropped: the proxy reads the new config, or hands its sockets to the new package's binary, which is why the unit starts it from `/etc/upstreamer/upstreamer`. the reload is `upstreamer reload`, which waits for the proxy and fails when the reload did, so a switch the proxy did not take fails instead of looking fine, and the old proxy keeps serving. a switch that changes the unit itself restarts it, with the listening sockets parked in systemd's file descriptor store, so connections made in between wait instead of being refused. [the config reference](docs/config.md#upgrading-without-a-restart-linux) says what an upgrade keeps and what it does not.

`metrics.enable` adds a site on `127.0.0.1:9100`. its port reaches `check` but not the firewall, because metrics are for a scraper on the same machine until you say `metrics.openFirewall`. `kubernetes.enable` picks the package built with kubernetes support and `kubernetes.kubeconfig` hands the kubeconfig to the unit as a systemd credential. `trustedProxies` takes the cidrs of whatever sits in front of you, or `cloudflare`.

load balancing, health checks and rate limits are keys of the route steps, so they have no module options. the module types routes as plain json and `check` validates them.

## without nix

the same config is a toml file. start from an example, check it, run it:

```sh
# print a commented config to start from, or see the others
upstreamer example > upstreamer.toml
upstreamer example --list

# validate it: every mistake with its json pointer, its site and step, and its line
upstreamer check --config upstreamer.toml

# serve it, and `kill -HUP` to reload
upstreamer run --config upstreamer.toml

# or reload it and learn whether that worked
upstreamer run --config upstreamer.toml --reload-socket /run/upstreamer.sock
upstreamer reload --reload-socket /run/upstreamer.sock
```

```toml
version = 1
listen.http = ["0.0.0.0:8080"]

[[sites]]
name = "app"
hosts = ["*"]
routes = [{ proxy = "http://127.0.0.1:3000" }]
```

`.toml` is toml and anything else is json, and both are one schema, so a toml file means exactly what the json the module writes would mean. a misspelt key is an error. [docs/config.md](docs/config.md) lists every key with its default, and `upstreamer convert` turns a json file into toml and back.

## command line

```sh
upstreamer check <config> [--expect-tcp 80,443] [--expect-udp 443]
upstreamer check --fragment <fragment>
upstreamer run <config> [--workers N] [--reload-socket <path>]
upstreamer reload --reload-socket <path>
upstreamer example [name | --list]
upstreamer convert <file>
```

`check` ends with what the config costs at run time, for the features it uses:

```text
ok: 3 sites, 14 steps, 3 pools (7 origins, 2 probed), 2 limits (265 KiB), metrics on (212 series)
```

## development

```sh
nix develop
cargo test
cargo clippy --all-targets -- -D warnings
nix flake check --no-build
```

every push and pull request runs `nix flake check` on x86_64-linux, nixos vm tests included, and on aarch64-darwin, every check but the vm tests on aarch64-linux, and `cargo test` in the dev shell on x86_64-linux with caddy, h2load and an http/3 curl, so the differential suite against caddy runs instead of skipping. its commits must follow conventional commits. the version lives in `Cargo.toml`, with `Cargo.lock` agreeing, and a pull request must raise it unless labeled `no-release`. a push to `main` that brings a version with no release yet builds upstreamer for x86_64-linux, aarch64-linux and aarch64-darwin, pushes it to `https://cache.r3dlust.com` (key `cache.r3dlust.com-1:Wdkf9mes2ued0P7C7CL3Jax1b4KPuJwQpM3h4G/Z+yI=`) pinned as `upstreamer-<system>`, then tags it `v<version>` and releases it.

[docs/config.md](docs/config.md) is the reference for the config, and [docs/architecture.md](docs/architecture.md) maps the modules, the request path and the nix side.

## license

[MIT](LICENSE)
