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
        concatMap
        filter
        filterAttrs
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
              description = "More host names answered by this virtual host. They join its certificate's names.";
            };

            tls = {
              enable = mkOption {
                type = types.bool;
                default = true;
                description = "Serve over TLS (HTTPS on TCP, and HTTP/3 on UDP when `http3`). Off: plain HTTP.";
              };

              acmeCert = mkOption {
                type = types.nullOr types.str;
                default = if config.tls.enable && config.tls.certFile == null then config.serverName else null;
                defaultText = lib.literalExpression "serverName, when tls.enable and no certFile";
                example = "example.com";
                description = ''
                  The `security.acme.certs` entry this host uses. The module creates it when no
                  other module does, and adds this host's names to it, so hosts that share a
                  certificate (www., blog.) only name it here.
                '';
              };

              certFile = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "PEM certificate chain not managed by ACME (e.g. the tailscale certificate). Kept as a string so it is never copied into the store.";
              };

              keyFile = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Private key for `certFile`.";
              };

              redirectHttp = mkOption {
                type = types.bool;
                default = true;
                description = "Answer plain HTTP requests for this host with a 308 to https.";
              };
            };

            http3 = mkOption {
              type = types.bool;
              default = cfg.http3;
              defaultText = lib.literalExpression "config.services.upstreamer.http3";
              description = "Serve HTTP/3 and advertise it with Alt-Svc.";
            };

            listen = mkOption {
              type = types.listOf (
                types.submodule {
                  options = {
                    addr = mkOption {
                      type = types.nullOr types.str;
                      default = null;
                      description = "Address; null binds every address in `services.upstreamer.listen.addresses`.";
                    };
                    port = mkOption { type = types.port; };
                  };
                }
              );
              default = [ ];
              description = "Addresses for this host instead of the defaults (80 for plain hosts, 443 for TLS hosts).";
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
              description = ''
                Ordered route steps, `{ name?; when?; <action>; }`, in upstreamer's route schema.
                Lists from several modules concatenate; use lib.mkBefore/mkAfter to order them.
              '';
            };

            errors = mkOption {
              type = types.listOf json;
              default = [ ];
              description = "Error routes, `{ status?; routes; }`, first match by status.";
            };

            proxy = mkOption {
              type = types.nullOr (types.either types.str json);
              default = null;
              example = "http://127.0.0.1:8080";
              description = ''
                Short form for a reverse-proxy host: appended as the last route step,
                `{ proxy = <this>; }`. A string is the upstream URL; an attribute set is the full
                proxy step (`to`, `tlsSkipVerify`, `headers`, `timeouts`).
              '';
            };
          };
        };

      vhosts = attrValues cfg.virtualHosts;
      tlsHosts = filter (v: v.tls.enable) vhosts;
      acmeHosts = filter (v: v.tls.acmeCert != null) tlsHosts;
      certNames = unique (map (v: v.tls.acmeCert) acmeHosts);
      namesOf = v: [ v.serverName ] ++ v.serverAliases;
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
              inherit (v.tls) redirectHttp;
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

      udpPorts = optionals (any (v: v.tls.enable && v.http3) vhosts) [ cfg.listen.httpsPort ];

      usedPorts = unique (
        concatMap (
          v:
          if v.listen != [ ] then
            map (l: l.port) v.listen
          else if v.tls.enable then
            [ cfg.listen.httpsPort ] ++ optional v.tls.redirectHttp cfg.listen.httpPort
          else
            [ cfg.listen.httpPort ]
        ) vhosts
      );
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
          description = "Worker threads, one per core. Null: one per CPU the service may run on.";
        };

        http3 = mkOption {
          type = types.bool;
          default = true;
          description = "Default for each virtual host's `http3`.";
        };

        ktls = mkOption {
          type = types.bool;
          default = true;
          description = "Offload TLS records to the kernel after handshakes (loads the `tls` module).";
        };

        openFirewall = mkOption {
          type = types.bool;
          default = true;
          description = "Open the TCP ports of every virtual host, and UDP for HTTP/3.";
        };

        listen = {
          addresses = mkOption {
            type = types.listOf types.str;
            default = [
              "0.0.0.0"
              "[::]"
            ];
            description = "Addresses bound by default. Wildcards, so binding never waits for an interface.";
          };
          httpPort = mkOption {
            type = types.port;
            default = 80;
          };
          httpsPort = mkOption {
            type = types.port;
            default = 443;
          };
        };

        acme.group = mkOption {
          type = types.str;
          default = "upstreamer";
          description = ''
            Default group of the ACME certificates this module creates. A certificate another
            service also reads can set its own group in security.acme.certs; the proxy joins
            whatever group each of its certificates has.
          '';
        };

        settings = mkOption {
          type = json;
          default = { };
          example = {
            timeouts.keepAlive = "120s";
            limits.maxHeadBytes = 65536;
          };
          description = "Top-level settings merged over the generated config (timeouts, limits).";
        };

        virtualHosts = mkOption {
          type = types.attrsOf (types.submodule vhostOptions);
          default = { };
          description = "Virtual hosts. Several modules may define the same host; their options merge.";
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
          map (v: {
            assertion =
              v.tls.enable -> (v.tls.acmeCert != null) != (v.tls.certFile != null && v.tls.keyFile != null);
            message = "services.upstreamer.virtualHosts.${v.serverName}.tls: set exactly one of acmeCert or certFile+keyFile.";
          }) vhosts
          ++ map (v: {
            assertion = v.tls.acmeCert == null || !(lib.hasInfix "*" v.tls.acmeCert);
            message = "services.upstreamer.virtualHosts.${v.serverName}: name the certificate of a wildcard host with tls.acmeCert.";
          }) vhosts;

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
            TimeoutStopSec = "15s";

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
