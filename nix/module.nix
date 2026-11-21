# services.upstreamer: the NixOS module (flake output nixosModules.default), and the checks that
# evaluate it for the example hosts in ./examples.
#
# A virtual host's certificate comes from one of three places: a NixOS ACME certificate
# (`tls.acmeCert`, the default), files (`tls.certFile`, `tls.keyFile`), or issuance by the proxy
# itself (`tls.acme`). For the first the module owns everything: which security.acme certs exist
# for virtual hosts, their names (derived from the hosts that use them), the group the proxy
# reads them through, reload on renewal, and boot ordering. lego defaults (DNS provider,
# credentials, email) stay with the host, in security.acme.defaults. For the third it provides
# the proxy a state directory for the account key and the certificates.
#
# Routes are typed as JSON values, not as a recursive Nix submodule tree: the schema is
# defined once, in upstreamer's Rust config types, and the config file is validated at build
# time by `upstreamer check`, so a bad route fails `nixos-rebuild build` with the option's
# JSON pointer and step name.
{ self, nixpkgs, ... }:
{
  flake.nixosModules.default =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      inherit (lib)
        any
        attrValues
        concatLists
        concatMap
        filter
        genAttrs
        mapAttrsToList
        mkEnableOption
        mkIf
        mkOption
        optional
        optionalAttrs
        optionals
        recursiveUpdate
        subtractLists
        types
        unique
        ;

      cfg = config.services.upstreamer;
      json = (pkgs.formats.json { }).type;

      vhostOptions =
        { name, config, ... }:
        {
          options = {
            serverName = mkOption {
              type = types.str;
              default = name;
              description = ''
                The host this virtual host answers: an exact name, `*.example.com`, or `*` for any
                host (plain HTTP catch-alls).
              '';
            };

            serverAliases = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [ "www.example.com" ];
              description = ''
                More host names this virtual host answers. With an ACME certificate, they are
                added to the certificate's names.
              '';
            };

            tls = {
              enable = mkOption {
                type = types.bool;
                default = true;
                description = ''
                  Serve HTTPS (and HTTP/3 when `http3` is on). The certificate is a NixOS ACME one
                  named by `tls.acmeCert` (by default, one named after `serverName`), the files
                  `tls.certFile` and `tls.keyFile`, or one the proxy issues itself (`tls.acme`).
                  Off: plain HTTP, and the `tls.*` certificate options must stay unset.
                '';
              };

              acmeCert = mkOption {
                type = types.nullOr types.str;
                default =
                  if
                    config.tls.enable
                    && config.tls.certFile == null
                    && config.tls.keyFile == null
                    && config.tls.acme == null
                  then
                    config.serverName
                  else
                    null;
                defaultText = lib.literalExpression "serverName, when tls.enable and none of certFile, keyFile and acme is set";
                example = "example.com";
                description = ''
                  Name of the `security.acme.certs` entry this host's certificate comes from. The
                  module declares that entry (its `domain` defaults to this name), adds the
                  `serverName` and `serverAliases` of every host that uses it to its
                  `extraDomainNames`, gives the proxy read access to it and reloads the proxy
                  when it is renewed. Hosts that share one certificate (`www.`, `blog.`) all name
                  it here; a wildcard host (`*.example.com`) names its base domain.

                  Issuance settings (DNS provider, credentials, email) come from
                  `security.acme.defaults`, or from `security.acme.certs.<name>` for one
                  certificate. A certificate that other services read too keeps its own `group`
                  and `reloadServices` there; the proxy joins that group and is added to its
                  reload list.

                  Until the first issuance finishes, the proxy answers this host's names with a
                  self-signed certificate and switches to the real one on the reload that
                  follows it, so a new host never delays the others.
                '';
              };

              certFile = mkOption {
                type = types.nullOr types.str;
                default = null;
                example = "/var/lib/tailscale/certs/host.tailnet.ts.net.crt";
                description = ''
                  PEM certificate chain from outside ACME (a tailscale certificate, say). A path
                  as a string, so the file is never copied into the Nix store. The proxy reads it
                  at start and on every reload; replace the file, then `systemctl reload
                  upstreamer`.
                '';
              };

              keyFile = mkOption {
                type = types.nullOr types.str;
                default = null;
                example = "/var/lib/tailscale/certs/host.tailnet.ts.net.key";
                description = "PEM private key for `certFile`, as a string path (never copied into the Nix store).";
              };

              acme = mkOption {
                type = types.nullOr (
                  types.submodule {
                    options = {
                      email = mkOption {
                        type = types.str;
                        example = "ops@example.com";
                        description = "The contact address of the ACME account the CA registers.";
                      };
                      directory = mkOption {
                        type = types.nullOr types.str;
                        default = null;
                        example = "https://acme-staging-v02.api.letsencrypt.org/directory";
                        description = "The CA's directory URL. Null: Let's Encrypt's production directory.";
                      };
                      challenge = mkOption {
                        type = types.enum [
                          "http-01"
                          "tls-alpn-01"
                        ];
                        default = "http-01";
                        description = ''
                          How the CA validates the host's names. `http-01` fetches a token over
                          plain HTTP on `services.upstreamer.listen.httpPort`, which the module
                          opens; `tls-alpn-01` validates over the HTTPS port and needs no plain
                          HTTP port.
                        '';
                      };
                    };
                  }
                );
                default = null;
                example = {
                  email = "ops@example.com";
                };
                description = ''
                  Get this host's certificate from an ACME CA (Let's Encrypt unless `directory`
                  says otherwise), issued and renewed by the proxy itself, without
                  `security.acme` and without any DNS provider. The CA reaches the host over
                  the Internet, so every name of the host (`serverName` and `serverAliases`)
                  must resolve to this machine and be a plain DNS name: wildcards and IP
                  addresses cannot be issued this way, and `upstreamer check` rejects them.

                  The account key and the issued certificates are kept in
                  `services.upstreamer.acme.stateDirectory`. Until the first issuance finishes,
                  the host's names are answered with a self-signed certificate, and the issued
                  one replaces it without a reload.

                  An alternative to `acmeCert`, `certFile` and `keyFile`: a host sets one of the
                  three.
                '';
              };

              redirectHttp = mkOption {
                type = types.bool;
                default = true;
                description = ''
                  Answer plain HTTP requests for this host's names, on `services.upstreamer.listen.httpPort`,
                  with a 308 redirect to https. Only for hosts on the default addresses: a host
                  with its own `listen` serves exactly those.
                '';
              };
            };

            http3 = mkOption {
              type = types.bool;
              default = cfg.http3;
              defaultText = lib.literalExpression "config.services.upstreamer.http3";
              description = "Serve HTTP/3 (QUIC on UDP) beside HTTPS and advertise it with `Alt-Svc`. TLS hosts only.";
            };

            listen = mkOption {
              type = types.listOf (
                types.submodule {
                  options = {
                    addr = mkOption {
                      type = types.nullOr types.str;
                      default = null;
                      example = "127.0.0.1";
                      description = "IP address, IPv6 in brackets (`[::1]`). Null: every address in `services.upstreamer.listen.addresses`.";
                    };
                    port = mkOption {
                      type = types.port;
                      description = "TCP port (and UDP port for HTTP/3 on a TLS host).";
                    };
                  };
                }
              );
              default = [ ];
              example = [ { port = 8080; } ];
              description = ''
                Where this host is served, instead of the defaults (`listen.httpPort` for plain
                hosts, `listen.httpsPort` for TLS hosts). A TLS host serves HTTPS on each, and
                HTTP/3 on the same UDP ports when `http3` is on; it gets no HTTP redirect.
                `openFirewall` opens these ports.
              '';
            };

            headers = mkOption {
              type = types.attrsOf (types.nullOr types.str);
              default = { };
              example = {
                X-Frame-Options = "DENY";
                Server = null;
              };
              description = ''
                Site headers: set on (string) or removed from (null) every response of this host,
                proxied, static, redirect and error responses alike. Values are templates
                (`{host}`, `{vars.x}`, ...). Merged across modules.
              '';
            };

            routes = mkOption {
              type = types.listOf json;
              default = [ ];
              example = lib.literalExpression ''
                [
                  {
                    name = "api";
                    when.path = "/api/*";
                    proxy = "http://127.0.0.1:8080";
                  }
                  { headers.Cache-Control = "no-cache"; }
                  { files.root = "''${pkgs.my-site}"; }
                ]
              '';
              description = ''
                Ordered route steps; a request runs them top to bottom. A step is
                `{ name?; when?; <one action>; }`:

                - `when` is a matcher whose keys must all hold (`path`, `pathRegex`, `method`,
                  `header`, `headerRegex`, `query`, `value` with `in` or `regex`, `file`,
                  `after`); `all`, `any` and `none` take lists of matchers.
                - Actions that change the request or the pending response and continue:
                  `set`, `rewrite`, `stripPrefix`, `tryFiles`, `headers`, `requestHeaders`,
                  `encode`.
                - `limit = { rate = "50/s"; burst; key; keys; }` takes a token from the bucket of
                  the request's key (default `"{remote_net}"`: an IPv4 address, or an IPv6
                  /64) and answers 429 with `Retry-After` through the error routes when it is
                  empty. It applies to the requests its `when` matches, at its place in the
                  list.
                - Actions that answer and end routing: `proxy`, `files`, `respond`, `redirect`,
                  `error`, and `metrics = { }`, which answers with the Prometheus exposition
                  (see `services.upstreamer.metrics`).
                - `routes` nests steps; `firstOf` runs only the first step whose `when` holds;
                  `include` splices the steps of a JSON fragment file (a store path, typically
                  generated by a package's build).

                A request that reaches the end without an answer gets 404. Strings are
                templates (`{host}`, `{path}`, `{query}`, `{remote_host}`, `{remote_net}`,
                `{scheme}`, `{vars.x}`, and `{re.1}` for a capture of the step's own
                `pathRegex`; in an error route, `{err.retry_after}`).

                The steps are plain attribute sets serialised to JSON. `upstreamer check`
                validates them when the system is built, so a mistake fails the build and names
                the step. Lists from several modules concatenate; order them with
                `lib.mkBefore` and `lib.mkAfter`.
              '';
            };

            errors = mkOption {
              type = types.listOf json;
              default = [ ];
              example = [
                {
                  status = [ 404 ];
                  routes = [ { respond.body = "Not here"; } ];
                }
              ];
              description = ''
                Error routes, `{ status?; routes; }`, tried in order for an error response (an
                `error` step, a missing file, an unreachable upstream); the first whose `status`
                list holds the code (absent: every error) runs its `routes`. A response
                there keeps the error's status unless it names another.
              '';
            };

            accessLog = {
              enable = mkOption {
                type = types.bool;
                default = false;
                description = ''
                  Write an access log for this host: one JSON object per line for every request it
                  answers, and for every WebSocket or other upgraded connection once it closes.
                  The fields, always present and in this order:

                  - `ts`: when the response or tunnel ended, UTC, RFC 3339 with milliseconds
                    (`"2026-11-14T08:49:37.123Z"`).
                  - `remote_ip`, `remote_port`: the client's address.
                  - `host`: the host name the request was matched by (lowercase, without port).
                  - `method`, `target`: as the client sent them (the target before any
                    `rewrite` or `stripPrefix`).
                  - `proto`: `"HTTP/1.0"`, `"HTTP/1.1"`, `"HTTP/2"` or `"HTTP/3"`.
                  - `user_agent`, `referer`: the request's header, or `null`.
                  - `status`: the status sent (101 for an upgraded connection).
                  - `bytes`: body bytes sent after the response head (over HTTP/1.1 as on the
                    wire, chunk syntax included); for an upgraded connection, the bytes relayed
                    to the client.
                  - `duration`: seconds, to the microsecond, from the host's choice to the end of
                    the response or tunnel.
                  - `upstream`: the `host:port` of the last `proxy` step that ran, or `null`.

                  Strings are JSON-escaped; an invalid UTF-8 sequence in a header becomes U+FFFD.

                  Each worker buffers lines and appends them in batches, at the latest a second
                  after a request ends; lines are never split or interleaved. When the disk is
                  full the lines are dropped and counted in the journal, and requests are not
                  slowed. The module rotates the files daily with logrotate, which reloads the
                  service so it reopens them.
                '';
              };

              path = mkOption {
                type = types.strMatching "/.*";
                default = "/var/log/upstreamer/access-${lib.replaceStrings [ "/" " " ] [ "_" "_" ] name}.log";
                defaultText = lib.literalExpression ''"/var/log/upstreamer/access-''${name}.log"'';
                description = ''
                  The log file. Hosts that name the same file share it. The default directory is
                  the service's `LogsDirectory`; a file elsewhere needs a directory that exists
                  and that the service's dynamic user may write to.
                '';
              };
            };

            proxy = mkOption {
              type = types.nullOr (types.either types.str json);
              default = null;
              example = "http://127.0.0.1:8080";
              description = ''
                Short form for a reverse-proxy host: appended as the last route step,
                `{ proxy = <this>; }`. A string is the upstream URL (`http://`, or `https://`
                for a TLS upstream); an attribute set is the full proxy step:

                - `to`: an origin URL, a list of origins (each a URL or `{ url; weight; }`), or
                  an origin source, `{ kubernetes = { namespace; service or selector; port;
                  scheme; serverName; }; }` (needs `services.upstreamer.kubernetes.enable`).
                - `balance`: `"roundRobin"` (the default), `"leastRequests"`, `"p2c"`, or
                  `{ hash = "<template>"; }` for consistent hashing of a request key such as
                  `"{cookie.session}"`.
                - `retries`: further attempts on other origins after a failed attempt of a
                  request that may be replayed.
                - `failStatuses`: origin statuses that count as a failed attempt.
                - `health`: `passive = { maxFails; cooldown; }` ejects an origin after
                  consecutive failures; `active = { path; interval; timeout; expect;
                  healthyAfter; unhealthyAfter; host; }` probes it.
                - `tlsSkipVerify`, `headers` for request headers sent upstream, `timeouts`.

                The client's `Host` is passed through, and `X-Forwarded-For`,
                `X-Forwarded-Proto` and `X-Forwarded-Host` are set. The reference of every key,
                with its default, is `docs/config.md` in the upstreamer repository.
              '';
            };
          };
        };

      vhosts = attrValues cfg.virtualHosts;
      tlsHosts = filter (v: v.tls.enable) vhosts;
      acmeHosts = filter (v: v.tls.acmeCert != null) tlsHosts;
      # Hosts whose certificate the proxy issues itself.
      selfIssued = filter (v: v.tls.enable && v.tls.acme != null) vhosts;
      stateDir = cfg.acme.stateDirectory;
      # A name with `*` is not a valid security.acme.certs entry (its unit names would be
      # rejected before any assertion could explain why); the wildcard assertion reports it.
      certNames = filter (c: !(lib.hasInfix "*" c)) (unique (map (v: v.tls.acmeCert) acmeHosts));
      namesOf = v: [ v.serverName ] ++ v.serverAliases;
      allNames = concatMap namesOf vhosts;
      hostsOfCert = c: concatMap namesOf (filter (v: v.tls.acmeCert == c) acmeHosts);
      certDir = c: config.security.acme.certs.${c}.directory;
      certGroups = unique (map (c: config.security.acme.certs.${c}.group) certNames);

      hostPort = addr: port: "${addr}:${toString port}";
      defaultAddrs = port: map (a: hostPort a port) cfg.listen.addresses;

      site =
        name: v:
        {
          inherit name;
          hosts = namesOf v;
          tls =
            if !v.tls.enable then
              null
            else
              {
                redirectHttp = v.tls.redirectHttp && v.listen == [ ];
                inherit (v) http3;
              }
              // (
                if v.tls.acme != null then
                  {
                    acme = {
                      inherit (v.tls.acme) email challenge;
                    }
                    // optionalAttrs (v.tls.acme.directory != null) { inherit (v.tls.acme) directory; };
                  }
                else
                  {
                    cert = if v.tls.certFile != null then v.tls.certFile else "${certDir v.tls.acmeCert}/fullchain.pem";
                    key = if v.tls.keyFile != null then v.tls.keyFile else "${certDir v.tls.acmeCert}/key.pem";
                  }
              );
          listen =
            if v.listen == [ ] then
              null
            else
              concatMap (
                l: if l.addr != null then [ (hostPort l.addr l.port) ] else defaultAddrs l.port
              ) v.listen;
          inherit (v) headers errors;
          routes = v.routes ++ optional (v.proxy != null) { inherit (v) proxy; };
        }
        // optionalAttrs v.accessLog.enable { accessLog = v.accessLog.path; };

      logDir = "/var/log/upstreamer";
      logPaths = unique (map (v: v.accessLog.path) (filter (v: v.accessLog.enable) vhosts));
      # Directories of logs outside the LogsDirectory, made writable through ProtectSystem
      # ("-": a directory that does not exist does not fail the unit).
      outsideLogDirs = unique (map dirOf (filter (p: dirOf p != logDir) logPaths));

      # The metrics endpoint is a site of its own, on its own listener, so no virtual host's
      # routes, TLS or access rules apply to it.
      metricsSite = {
        name = "_metrics";
        hosts = [ "*" ];
        tls = null;
        listen = cfg.metrics.listen;
        routes = [
          {
            when.path = cfg.metrics.path;
            metrics = { };
          }
        ];
      };

      settings = recursiveUpdate (
        {
          version = 1;
          inherit (cfg) workers http3;
          listen = {
            http = defaultAddrs cfg.listen.httpPort;
            https = defaultAddrs cfg.listen.httpsPort;
          };
          sites = mapAttrsToList site cfg.virtualHosts ++ optional cfg.metrics.enable metricsSite;
        }
        // optionalAttrs (cfg.trustedProxies != null) { inherit (cfg) trustedProxies; }
        // optionalAttrs (selfIssued != [ ]) { acme.stateDirectory = stateDir; }
      ) cfg.settings;

      # Validated at build time; a bad route fails the system build, never the running proxy.
      # The firewall ports below are computed here in Nix; `check` compares them with the listeners
      # the compiler derives from the same sites and fails the build if they differ.
      configJSON = pkgs.writeText "upstreamer.json" (builtins.toJSON settings);
      checkedConfig = pkgs.runCommand "upstreamer-config.json" { nativeBuildInputs = [ cfg.package ]; } ''
        upstreamer check --config ${configJSON} \
          --expect-tcp "${lib.concatMapStringsSep "," toString usedPorts}" \
          --expect-udp "${lib.concatMapStringsSep "," toString udpPorts}"
        cp ${configJSON} "$out"
      '';

      # Ports a host is served on (TCP, and UDP for HTTP/3), besides the HTTP redirect.
      ports =
        v:
        if v.listen != [ ] then
          map (l: l.port) v.listen
        else if v.tls.enable then
          [ cfg.listen.httpsPort ]
        else
          [ cfg.listen.httpPort ];

      # `http-01` validation arrives on the plain HTTP port.
      needsHttpPort = v: v.tls.enable && v.tls.acme != null && v.tls.acme.challenge == "http-01";

      # The ports the virtual hosts are served on, and the firewall opens these.
      hostPorts = unique (
        concatMap (
          v:
          ports v
          ++ optional (
            (v.tls.enable && v.tls.redirectHttp && v.listen == [ ]) || needsHttpPort v
          ) cfg.listen.httpPort
        ) vhosts
      );
      # "127.0.0.1:9100" and "[::1]:9100" are both port 9100.
      metricsPorts = unique (
        map (a: lib.toInt (lib.last (lib.splitString ":" a))) (
          optionals cfg.metrics.enable cfg.metrics.listen
        )
      );
      # What `check --expect-tcp` compares with the listeners the sites derive.
      usedPorts = unique (hostPorts ++ metricsPorts);
      firewallPorts = unique (hostPorts ++ optionals cfg.metrics.openFirewall metricsPorts);
      udpPorts = unique (concatMap (v: optionals (v.tls.enable && v.http3) (ports v)) vhosts);

      # "10s" -> 10, "1500ms" -> 2 (rounded up), as the shutdown timeout's type allows.
      seconds =
        d:
        let
          m = builtins.match "([0-9]+)(ms|s|m|h)" d;
          n = lib.toIntBase10 (builtins.head m);
        in
        {
          ms = (n + 999) / 1000;
          s = n;
          m = n * 60;
          h = n * 3600;
        }
        .${builtins.elemAt m 1};
    in
    {
      options.services.upstreamer = {
        enable = mkEnableOption "upstreamer, the reverse proxy and static file server";

        package = mkOption {
          type = types.package;
          default =
            if cfg.kubernetes.enable then
              self.packages.${pkgs.stdenv.hostPlatform.system}.kubernetes
            else
              self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          defaultText = lib.literalExpression "upstreamer.packages.\${system}.default, or .kubernetes when `kubernetes.enable` is set";
          description = "The upstreamer package (also runs `upstreamer check` at build time).";
        };

        workers = mkOption {
          type = types.nullOr types.ints.positive;
          default = null;
          description = "Worker threads, each pinned to one CPU. Null: one per CPU the service may run on.";
        };

        http3 = mkOption {
          type = types.bool;
          default = true;
          description = "Default of every virtual host's `http3`.";
        };

        ktls = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Hand TLS record encryption to the kernel after each handshake (kTLS), so files are
            sent with sendfile. Loads the `tls` kernel module at boot when a TLS host exists.
            Without kernel support, TLS stays in user space.
          '';
        };

        openFirewall = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Open the TCP ports the virtual hosts are served on (with their HTTP redirect), and
            the UDP ports of TLS hosts with `http3`, on every interface. Off: open them
            yourself, for example on one interface with `networking.firewall.interfaces`.
          '';
        };

        listen = {
          addresses = mkOption {
            type = types.listOf types.str;
            default = [
              "0.0.0.0"
              "[::]"
            ];
            description = ''
              Addresses every virtual host without its own `listen` is served on (IPv6 in
              brackets). The default wildcards (`[::]` bound IPv6-only) let the proxy start before
              any interface has an address, so it needs no ordering after the network.
            '';
          };
          httpPort = mkOption {
            type = types.port;
            default = 80;
            description = "Port of plain HTTP hosts and of the HTTPS redirect.";
          };
          httpsPort = mkOption {
            type = types.port;
            default = 443;
            description = "Port of TLS hosts: HTTPS on TCP, HTTP/3 on UDP.";
          };
        };

        acme.group = mkOption {
          type = types.str;
          default = "upstreamer-certs";
          description = ''
            Default group of the ACME certificates the virtual hosts use; the module creates it.
            It cannot be `upstreamer`, the name of the unit's dynamic user and group.
            A certificate another service reads too sets its own group in
            `security.acme.certs.<name>.group`; the proxy joins the group of each of its
            certificates.
          '';
        };

        acme.stateDirectory = mkOption {
          type = types.strMatching "/var/lib/.+";
          default = "/var/lib/upstreamer";
          description = ''
            Where the proxy keeps the account key and the certificates it issues for hosts
            with `tls.acme`. It is the service's `StateDirectory`, so it lies under `/var/lib`,
            belongs to the service's dynamic user and is readable by nobody else.
          '';
        };

        trustedProxies = mkOption {
          type = types.nullOr (
            types.submodule {
              options = {
                from = mkOption {
                  type = types.listOf types.str;
                  example = [
                    "cloudflare"
                    "10.0.0.0/8"
                  ];
                  description = ''
                    The peers whose word about the client's address is believed: CIDR ranges
                    (`10.0.0.0/8`, `2001:db8::/32`), and `cloudflare` for Cloudflare's published
                    ranges.
                  '';
                };
                header = mkOption {
                  type = types.str;
                  example = "CF-Connecting-IP";
                  description = ''
                    The request header that carries the client's address: `CF-Connecting-IP`,
                    `X-Real-IP`, or `X-Forwarded-For` (its rightmost address that is not itself
                    a trusted proxy).
                  '';
                };
              };
            }
          );
          default = null;
          example = {
            from = [ "cloudflare" ];
            header = "CF-Connecting-IP";
          };
          description = ''
            Behind a CDN or a load balancer the TCP peer is the proxy in front, not the client.
            With this set, a request from one of the `from` peers has its client address taken
            from `header`, and that address is what `{remote_host}` (and `{remote_net}`) expand
            to, what the access log and the metrics record, and what rate-limit and hash keys
            see. Requests from any other peer keep their own address and their header is
            ignored. The peer's own address stays available as `{peer_host}`. Null: the TCP peer
            is always the client.
          '';
        };

        metrics = {
          enable = mkEnableOption ''
            Prometheus metrics: a site on `metrics.listen` whose `metrics.path` answers with the
            exposition. Collection runs only while a metrics step exists, so off costs nothing.
            Request series are labelled by virtual host, by route step `name`, and by status
            class'';
          listen = mkOption {
            type = types.listOf types.str;
            default = [
              "127.0.0.1:9100"
              "[::1]:9100"
            ];
            description = "Addresses of the metrics listener (plain HTTP).";
          };
          path = mkOption {
            type = types.strMatching "/.*";
            default = "/metrics";
            description = "Path of the exposition; every other path answers 404.";
          };
          openFirewall = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Open the metrics port. Off by default even when `openFirewall` is on: metrics are
              for a scraper on this host or on a private network you open yourself.
            '';
          };
        };

        kubernetes = {
          enable = mkEnableOption ''
            origins discovered from Kubernetes (`proxy.to.kubernetes`). Switches the default
            `package` to the build with Kubernetes support'';
          kubeconfig = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "/etc/rancher/k3s/upstreamer.yaml";
            description = ''
              Kubeconfig for the API server, as a string path (never copied to the Nix store).
              Passed to the unit as a systemd credential, so the dynamic user reads it without
              a group. The credentials in it must be inline (a bearer `token` or
              `client-certificate-data` and `client-key-data`): files it names are read by the
              dynamic user, who may not be able to. Null: the in-cluster service account, for a
              proxy that runs in a pod.
            '';
          };
        };

        settings = mkOption {
          type = types.submodule {
            freeformType = json;
            options.timeouts.shutdown = mkOption {
              type = types.strMatching "[0-9]+(ms|s|m|h)";
              default = "10s";
              description = ''
                How long requests in flight and open tunnels may run after the service is told
                to stop (restart, shutdown) before they are cut. The unit's `TimeoutStopSec`
                follows it.
              '';
            };
          };
          default = { };
          example = {
            timeouts.keepAlive = "120s";
            limits.maxHeadBytes = 65536;
          };
          description = ''
            Top-level settings of upstreamer's config file, merged over what the module
            generates: `timeouts` (`header`, `keepAlive`, `shutdown`; durations such
            as `"300ms"`, `"5s"`, `"2m"`, `"1h"`) and `limits` (`maxHeadBytes`,
            `maxHeaderFields`, `maxStreams`). `docs/config.md` in the upstreamer repository
            lists every key.
          '';
        };

        virtualHosts = mkOption {
          type = types.attrsOf (types.submodule vhostOptions);
          default = { };
          example = lib.literalExpression ''
            {
              "app.example.com".proxy = "http://127.0.0.1:8080";
              "www.example.com".tls.acmeCert = "example.com";
              "example.com".routes = [ { files.root = "''${pkgs.my-site}"; } ];
            }
          '';
          description = ''
            Virtual hosts by name. A host is served over TLS with an ACME certificate named
            after it unless it says otherwise. Several modules may define the same host: a
            service's module can contribute its `routes` and `headers` while the machine's
            configuration sets its TLS.
          '';
        };

        configFile = mkOption {
          type = types.path;
          readOnly = true;
          default = checkedConfig;
          defaultText = lib.literalMD "the generated config, checked at build time";
          description = "The config upstreamer runs with.";
        };

        generatedSettings = mkOption {
          type = json;
          readOnly = true;
          internal = true;
          default = settings;
          description = "The config as a Nix value, before serialisation (for tests).";
        };
      };

      config = mkIf cfg.enable {
        assertions =
          concatLists (
            mapAttrsToList (
              name: v:
              let
                at = "services.upstreamer.virtualHosts.${lib.strings.escapeNixIdentifier name}.tls";
              in
              [
                {
                  assertion =
                    v.tls.enable
                    ->
                      lib.length (
                        filter lib.id [
                          (v.tls.acmeCert != null)
                          (v.tls.certFile != null && v.tls.keyFile != null)
                          (v.tls.acme != null)
                        ]
                      ) == 1;
                  message = "${at}: set one of acme, acmeCert, or both certFile and keyFile.";
                }
                {
                  assertion =
                    !v.tls.enable
                    -> v.tls.acmeCert == null && v.tls.certFile == null && v.tls.keyFile == null && v.tls.acme == null;
                  message = "${at}: acme, acmeCert, certFile and keyFile need tls.enable.";
                }
                {
                  assertion = v.tls.acmeCert == null || !(lib.hasInfix "*" v.tls.acmeCert);
                  message = "${at}.acmeCert: a wildcard host names its certificate, e.g. \"example.com\" for \"*.example.com\".";
                }
              ]
            ) cfg.virtualHosts
          )
          # A certificate for a name no host serves is almost always a misspelt acmeCert, and
          # its issuance would fail at run time; this fails the build instead.
          ++ map (
            c:
            let
              domain = config.security.acme.certs.${c}.domain;
            in
            {
              assertion = lib.elem domain allNames || lib.elem "*.${domain}" allNames;
              message = "services.upstreamer: tls.acmeCert \"${c}\" of ${lib.concatStringsSep ", " (hostsOfCert c)} names a certificate for ${domain}, which no virtual host serves.";
            }
          ) certNames
          ++ [
            {
              assertion = !(cfg.metrics.enable && cfg.virtualHosts ? "_metrics");
              message = "services.upstreamer.virtualHosts: `_metrics` names the site `metrics.enable` adds; give the virtual host another name.";
            }
            {
              assertion = cfg.kubernetes.kubeconfig == null || cfg.kubernetes.enable;
              message = "services.upstreamer.kubernetes.kubeconfig needs kubernetes.enable.";
            }
            {
              assertion = !(lib.elem "upstreamer" certGroups);
              message = "services.upstreamer: a certificate group is named upstreamer, the name of the unit's dynamic user and group; systemd will not start the unit while a static group has that name.";
            }
          ];

        security.acme.certs = genAttrs certNames (c: {
          domain = lib.mkDefault c;
          extraDomainNames = subtractLists [ c ] (unique (hostsOfCert c));
          group = lib.mkDefault cfg.acme.group;
          reloadServices = [ "upstreamer.service" ];
        });

        users.groups = mkIf (any (c: config.security.acme.certs.${c}.group == cfg.acme.group) certNames) {
          ${cfg.acme.group} = { };
        };

        environment.etc."upstreamer/config.json".source = cfg.configFile;

        systemd.services.upstreamer = {
          description = "upstreamer reverse proxy";
          wantedBy = [ "multi-user.target" ];
          # Start once each certificate's directory holds a certificate the proxy's groups can
          # read (acme-<name> puts a self-signed one in place and sets the directory's group),
          # and before the renewal that orders the real one: a host whose certificate is not
          # issued yet is served once ACME reloads us, the others with theirs from the start.
          wants = map (c: "acme-${c}.service") certNames;
          after = [ "network.target" ] ++ map (c: "acme-${c}.service") certNames;
          before = map (c: "acme-order-renew-${c}.service") certNames;
          # A switch that changes only the config reloads (no dropped connections); a new package
          # changes ExecStart and restarts.
          reloadTriggers = [ cfg.configFile ];
          unitConfig.StartLimitIntervalSec = 0;
          serviceConfig = {
            Type = "notify-reload";
            ExecStart = "${lib.getExe cfg.package} run --config /etc/upstreamer/config.json";
            Restart = "on-failure";
            RestartSec = "1s";
            # The drain, then a margin for the process to exit.
            TimeoutStopSec = seconds cfg.settings.timeouts.shutdown + 5;

            DynamicUser = true;
            SupplementaryGroups = certGroups;
            AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
            CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
            LimitNOFILE = 1048576;

            DevicePolicy = "closed";
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            NoNewPrivileges = true;
            PrivateDevices = true;
            PrivateTmp = true;
            ProcSubset = "pid";
            ProtectClock = true;
            ProtectControlGroups = true;
            ProtectHome = true;
            ProtectHostname = true;
            ProtectKernelLogs = true;
            ProtectKernelModules = true;
            ProtectKernelTunables = true;
            ProtectProc = "invisible";
            ProtectSystem = "strict";
            RemoveIPC = true;
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_INET6"
              "AF_UNIX"
            ];
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            SystemCallArchitectures = "native";
            LogsDirectory = mkIf (logPaths != [ ]) "upstreamer";
            # The account key and the issued certificates: readable by the service alone.
            StateDirectory = mkIf (selfIssued != [ ]) (lib.removePrefix "/var/lib/" stateDir);
            StateDirectoryMode = mkIf (selfIssued != [ ]) "0700";
            LoadCredential = optional (
              cfg.kubernetes.kubeconfig != null
            ) "kubeconfig:${cfg.kubernetes.kubeconfig}";
            Environment = optional (cfg.kubernetes.kubeconfig != null) "KUBECONFIG=%d/kubeconfig";
            ReadWritePaths = mkIf (outsideLogDirs != [ ]) (map (d: "-${d}") outsideLogDirs);
            # @system-service keeps sched_setaffinity (worker pinning) and setsockopt (kTLS).
            SystemCallFilter = [
              "@system-service"
              "~@privileged"
            ];
            UMask = "0077";
          };
        };

        # kTLS needs the tls ULP; ProtectKernelModules stops the service from autoloading it.
        boot.kernelModules = optionals (cfg.ktls && tlsHosts != [ ]) [ "tls" ];
        # Connections queued on a reuseport socket that closes (restart, removed listener) move to
        # a sibling socket instead of being reset.
        boot.kernel.sysctl."net.ipv4.tcp_migrate_req" = lib.mkDefault 1;

        # Rotation renames the files; the reload that follows makes the proxy open new ones.
        services.logrotate.settings.upstreamer = mkIf (logPaths != [ ]) (
          lib.mapAttrs (_: lib.mkDefault) {
            files = logPaths;
            frequency = "daily";
            rotate = 14;
            compress = true;
            # A line from a request that started before the reload may still land in the
            # rotated file; it is compressed at the next rotation instead.
            delaycompress = true;
            missingok = true;
            notifempty = true;
            sharedscripts = true;
            postrotate = "${config.systemd.package}/bin/systemctl try-reload-or-restart upstreamer.service";
          }
        );

        networking.firewall = mkIf cfg.openFirewall {
          allowedTCPPorts = firewallPorts;
          allowedUDPPorts = udpPorts;
        };
      };
    };

  perSystem =
    {
      pkgs,
      lib,
      self',
      ...
    }:
    {
      checks = import ./examples {
        inherit pkgs lib nixpkgs;
        module = self.nixosModules.default;
        package = self'.packages.default;
        packages = self.packages;
      };
    };
}
