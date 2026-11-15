# services.upstreamer: the NixOS module (flake output nixosModules.default), and the checks that
# evaluate it for the example hosts in ./examples.
#
# The module owns everything about the proxy's certificates: which security.acme certs exist
# for virtual hosts, their names (derived from the hosts that use them), the group the proxy
# reads them through, reload on renewal, and boot ordering. lego defaults (DNS provider,
# credentials, email) stay with the host, in security.acme.defaults.
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
                  Serve HTTPS (and HTTP/3 when `http3` is on). The certificate is an ACME one
                  named by `tls.acmeCert` (by default, one named after `serverName`), or the
                  files `tls.certFile` and `tls.keyFile`. Off: plain HTTP, and the `tls.*`
                  certificate options must stay unset.
                '';
              };

              acmeCert = mkOption {
                type = types.nullOr types.str;
                default =
                  if config.tls.enable && config.tls.certFile == null && config.tls.keyFile == null then
                    config.serverName
                  else
                    null;
                defaultText = lib.literalExpression "serverName, when tls.enable and no certFile or keyFile";
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
                - Actions that answer and end routing: `proxy`, `files`, `respond`, `redirect`,
                  `error`.
                - `routes` nests steps; `firstOf` runs only the first step whose `when` holds;
                  `include` splices the steps of a JSON fragment file (a store path, typically
                  generated by a package's build).

                A request that reaches the end without an answer gets 404. Strings are
                templates (`{host}`, `{path}`, `{query}`, `{remote_host}`, `{scheme}`,
                `{vars.x}`, and `{re.1}` for a capture of the step's own `pathRegex`).

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

            proxy = mkOption {
              type = types.nullOr (types.either types.str json);
              default = null;
              example = "http://127.0.0.1:8080";
              description = ''
                Short form for a reverse-proxy host: appended as the last route step,
                `{ proxy = <this>; }`. A string is the upstream URL (`http://`, or `https://`
                for a TLS upstream); an attribute set is the full proxy step (`to`,
                `tlsSkipVerify`, `headers` for request headers sent upstream, `timeouts`).
                The client's `Host` is passed through, and `X-Forwarded-For`,
                `X-Forwarded-Proto` and `X-Forwarded-Host` are set.
              '';
            };
          };
        };

      vhosts = attrValues cfg.virtualHosts;
      tlsHosts = filter (v: v.tls.enable) vhosts;
      acmeHosts = filter (v: v.tls.acmeCert != null) tlsHosts;
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

      site = name: v: {
        inherit name;
        hosts = namesOf v;
        tls =
          if !v.tls.enable then
            null
          else
            {
              cert = if v.tls.certFile != null then v.tls.certFile else "${certDir v.tls.acmeCert}/fullchain.pem";
              key = if v.tls.keyFile != null then v.tls.keyFile else "${certDir v.tls.acmeCert}/key.pem";
              redirectHttp = v.tls.redirectHttp && v.listen == [ ];
              inherit (v) http3;
            };
        listen =
          if v.listen == [ ] then
            null
          else
            concatMap (
              l: if l.addr != null then [ (hostPort l.addr l.port) ] else defaultAddrs l.port
            ) v.listen;
        inherit (v) headers errors;
        routes = v.routes ++ optional (v.proxy != null) { inherit (v) proxy; };
      };

      settings = recursiveUpdate {
        version = 1;
        inherit (cfg) workers http3;
        listen = {
          http = defaultAddrs cfg.listen.httpPort;
          https = defaultAddrs cfg.listen.httpsPort;
        };
        sites = mapAttrsToList site cfg.virtualHosts;
      } cfg.settings;

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

      usedPorts = unique (
        concatMap (
          v: ports v ++ optional (v.tls.enable && v.tls.redirectHttp && v.listen == [ ]) cfg.listen.httpPort
        ) vhosts
      );
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
          default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          defaultText = lib.literalExpression "upstreamer.packages.\${system}.default";
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
          default = "upstreamer";
          description = ''
            Default group of the ACME certificates the virtual hosts use; the module creates it.
            A certificate another service reads too sets its own group in
            `security.acme.certs.<name>.group`; the proxy joins the group of each of its
            certificates.
          '';
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
            `maxHeaderFields`, `maxStreams`).
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
                    v.tls.enable -> (v.tls.acmeCert != null) != (v.tls.certFile != null && v.tls.keyFile != null);
                  message = "${at}: set either acmeCert, or both certFile and keyFile.";
                }
                {
                  assertion =
                    !v.tls.enable -> v.tls.acmeCert == null && v.tls.certFile == null && v.tls.keyFile == null;
                  message = "${at}: acmeCert, certFile and keyFile need tls.enable.";
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
          ) certNames;

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
          after = [ "network.target" ];
          # Pull certificate issuance in at boot, but do not wait for it: a host whose certificate
          # does not exist yet is served once ACME reloads us; the others serve immediately.
          wants = map (c: "acme-${c}.service") certNames;
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

        networking.firewall = mkIf cfg.openFirewall {
          allowedTCPPorts = usedPorts;
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
      };
    };
}
