# upstreamer

![rust](https://img.shields.io/badge/rust-2024-orange?logo=rust)
![license](https://img.shields.io/badge/license-MIT-blue)

a reverse proxy and static file server for nixos hosts, configured with plain nix options.

> **under construction.** `upstreamer check` validates a config's schema and the nixos module evaluates. `upstreamer run` does not serve requests yet.

## what it is for

- tls with certificates from nixos acme, http/1.1, http/2 and http/3.
- reverse proxying to one origin per route, with websocket and other upgrades, streamed bodies and server-sent events.
- static files with precompressed sidecars, etag sidecars and conditional requests.
- routes as an ordered list of steps, such as `proxy`, `files`, `rewrite`, `headers` and `redirect`, each with an optional `when` matcher. third-party nixos modules can add steps to a host.
- reload without dropping connections, and a host whose certificate does not exist yet keeps the others serving.

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
    virtualHosts."app.example.com".proxy = "http://127.0.0.1:8080";
    virtualHosts."www.example.com".routes = [
      { when.path = "/api/*"; proxy = "http://127.0.0.1:9000"; }
      { files.root = "/srv/www"; }
    ];
  };
}
```

each virtual host gets tls with an acme certificate named after it unless you say otherwise. certificates come from dns-01 challenges, so the host sets its lego dns provider. the module creates the certificates, opens the firewall, and runs `upstreamer check` on the generated config while the system builds, so a bad route fails the build.

## command line

```sh
upstreamer check <config.json> [--expect-tcp 80,443] [--expect-udp 443]
upstreamer check --fragment <fragment.json>
upstreamer run <config.json> [--workers N]
```

## development

```sh
nix develop
cargo test
cargo clippy --all-targets -- -D warnings
nix flake check --no-build
```

[docs/architecture.md](docs/architecture.md) maps the modules, the request path and the nix side.

## license

[MIT](LICENSE)
