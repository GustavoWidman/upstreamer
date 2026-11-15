# Checks of the NixOS module on the example hosts.
#
# module-eval evaluates them, without building anything, and checks what the module derives
# from their virtual hosts: the config it emits (equal to tests/fixtures/config, which the Rust
# schema tests read), the ACME certificates and their names and groups, the unit, the firewall
# and the kernel modules. Each host's whole system is instantiated too, so a type error anywhere
# in the module fails here. It also evaluates misconfigured hosts and checks that the module's
# assertions reject each one with its message. The hosts get a stub package, so evaluating them for another system
# needs nothing built for it. `fixtures` in the dev shell rewrites tests/fixtures/config from
# its `hosts`.
#
# module-config (Linux) builds each host's config file with the real package, which runs
# `upstreamer check` on it exactly as a system build does.
{
  pkgs,
  lib,
  nixpkgs,
  module,
  package,
}:
let
  # NixOS hosts are Linux; a Darwin checker evaluates them for aarch64-linux.
  hostPlatform =
    if pkgs.stdenv.hostPlatform.isLinux then pkgs.stdenv.hostPlatform.system else "aarch64-linux";

  files = {
    edge = ./edge.nix;
    apps = ./apps.nix;
    desktop = ./desktop.nix;
    custom = ./custom.nix;
  };

  eval =
    upstreamer: file:
    (nixpkgs.lib.nixosSystem {
      modules = [
        module
        ./common.nix
        (
          { pkgs, ... }:
          {
            nixpkgs.hostPlatform = hostPlatform;
            services.upstreamer.package = upstreamer pkgs;
          }
        )
        file
      ];
    }).config;

  systems = lib.mapAttrs (_: eval (pkgs: pkgs.writeShellScriptBin "upstreamer" "")) files;

  sorted = lib.sort lib.lessThan;

  observed =
    c:
    let
      u = c.systemd.services.upstreamer;
    in
    {
      failedAssertions = failedAssertions c;
      certs = lib.mapAttrs (_: cert: {
        inherit (cert) domain group;
        extraDomainNames = sorted cert.extraDomainNames;
        reloadServices = sorted cert.reloadServices;
      }) c.security.acme.certs;
      unit = {
        inherit (u.serviceConfig) Type ExecStart TimeoutStopSec;
        SupplementaryGroups = sorted u.serviceConfig.SupplementaryGroups;
        wants = sorted u.wants;
      };
      tcp = sorted c.networking.firewall.allowedTCPPorts;
      udp = sorted c.networking.firewall.allowedUDPPorts;
      tlsModule = lib.elem "tls" c.boot.kernelModules;
      logs =
        let
          rotate = c.services.logrotate.settings.upstreamer or null;
        in
        {
          directory = u.serviceConfig.LogsDirectory or null;
          readWritePaths = u.serviceConfig.ReadWritePaths or [ ];
          rotated = if rotate == null then [ ] else rotate.files;
          rotation =
            if rotate == null then
              null
            else
              {
                inherit (rotate) frequency compress delaycompress;
                reloads = lib.hasSuffix "/bin/systemctl try-reload-or-restart upstreamer.service" rotate.postrotate;
              };
        };
    };

  noLogs = {
    directory = null;
    readWritePaths = [ ];
    rotated = [ ];
    rotation = null;
  };

  cert = domain: extraDomainNames: group: reloadServices: {
    inherit
      domain
      extraDomainNames
      group
      reloadServices
      ;
  };
  own = domain: cert domain [ ] "upstreamer-certs" [ "upstreamer.service" ];
  unit' = timeoutStopSec: groups: certs: {
    Type = "notify-reload";
    ExecStart = "${lib.getExe systems.edge.services.upstreamer.package} run --config /etc/upstreamer/config.json";
    # The default 10s drain, plus 5s to exit.
    TimeoutStopSec = timeoutStopSec;
    SupplementaryGroups = groups;
    wants = map (c: "acme-${c}.service") certs;
  };
  unit = unit' 15;

  expected = {
    edge = {
      failedAssertions = [ ];
      certs = lib.genAttrs [ "app.example.com" "cache.example.com" "s3.cache.example.com" ] own;
      unit = unit [ "upstreamer-certs" ] [ "app.example.com" "cache.example.com" "s3.cache.example.com" ];
      tcp = [
        80
        443
      ];
      udp = [ 443 ];
      tlsModule = true;
      logs = {
        directory = "upstreamer";
        readWritePaths = [ "-/srv/logs" ];
        rotated = [
          "/var/log/upstreamer/access-cache.example.com.log"
          "/srv/logs/s3.log"
        ];
        rotation = {
          frequency = "daily";
          compress = true;
          delaycompress = true;
          reloads = true;
        };
      };
    };
    apps = {
      failedAssertions = [ ];
      certs = lib.genAttrs [ "files.example.net" "play.example.net" "relay.example.net" ] own // {
        "dns.example.net" = cert "dns.example.net" [ ] "dns-certs" [
          "dns-server.service"
          "upstreamer.service"
        ];
        "mail.example.net" = cert "mail.example.net" [ ] "mail-certs" [ "upstreamer.service" ];
        "example.org" = cert "example.org" [ "blog.example.org" "www.example.org" ] "upstreamer-certs" [
          "upstreamer.service"
        ];
      };
      unit =
        unit
          [ "dns-certs" "mail-certs" "upstreamer-certs" ]
          [
            "dns.example.net"
            "example.org"
            "files.example.net"
            "mail.example.net"
            "play.example.net"
            "relay.example.net"
          ];
      tcp = [
        80
        443
      ];
      udp = [ 443 ];
      tlsModule = true;
      logs = noLogs;
    };
    desktop = {
      failedAssertions = [ ];
      certs = { };
      unit = unit [ ] [ ];
      tcp = [ ];
      udp = [ ];
      tlsModule = false;
      logs = noLogs;
    };
    custom = {
      failedAssertions = [ ];
      certs = {
        "admin.example.com" = own "admin.example.com";
        "preview.example.com" = cert "preview.example.com" [ "*.preview.example.com" ] "upstreamer-certs" [
          "upstreamer.service"
        ];
      };
      # A 30s drain.
      unit = unit' 35 [ "upstreamer-certs" ] [ "admin.example.com" "preview.example.com" ];
      tcp = [
        80
        443
        8080
        8443
      ];
      udp = [
        443
        8443
      ];
      tlsModule = true;
      logs = noLogs;
    };
  };

  # Misconfigured hosts, each with the assertion messages it must fail with.
  rejected = {
    cert-group-named-like-the-unit = {
      module.services.upstreamer = {
        acme.group = "upstreamer";
        virtualHosts."a.example.com".proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer: a certificate group is named upstreamer, the name of the unit's dynamic user and group; systemd will not start the unit while a static group has that name."
      ];
    };
    acme-and-files = {
      module.services.upstreamer.virtualHosts."a.example.com" = {
        tls = {
          acmeCert = "a.example.com";
          certFile = "/run/a.crt";
          keyFile = "/run/a.key";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.\"a.example.com\".tls: set either acmeCert, or both certFile and keyFile."
      ];
    };
    cert-without-key = {
      module.services.upstreamer.virtualHosts."a.example.com" = {
        tls.certFile = "/run/a.crt";
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.\"a.example.com\".tls: set either acmeCert, or both certFile and keyFile."
      ];
    };
    files-without-tls = {
      module.services.upstreamer.virtualHosts.plain = {
        tls = {
          enable = false;
          certFile = "/run/a.crt";
          keyFile = "/run/a.key";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.plain.tls: acmeCert, certFile and keyFile need tls.enable."
      ];
    };
    acme-without-tls = {
      module.services.upstreamer.virtualHosts.plain = {
        tls = {
          enable = false;
          acmeCert = "example.com";
        };
        proxy = "http://127.0.0.1:1";
      };
      messages = [
        "services.upstreamer.virtualHosts.plain.tls: acmeCert, certFile and keyFile need tls.enable."
      ];
    };
    unknown-acme-cert = {
      module.services.upstreamer.virtualHosts = {
        "example.com".proxy = "http://127.0.0.1:1";
        "www.example.com" = {
          tls.acmeCert = "exmaple.com";
          proxy = "http://127.0.0.1:1";
        };
      };
      messages = [
        "services.upstreamer: tls.acmeCert \"exmaple.com\" of www.example.com names a certificate for exmaple.com, which no virtual host serves."
      ];
    };
    unnamed-wildcard-cert = {
      module.services.upstreamer.virtualHosts."*.example.com".proxy = "http://127.0.0.1:1";
      messages = [
        "services.upstreamer.virtualHosts.\"*.example.com\".tls.acmeCert: a wildcard host names its certificate, e.g. \"example.com\" for \"*.example.com\"."
      ];
    };
  };

  # The emitted config, as JSON would carry it.
  hosts = lib.mapAttrs (
    _: c:
    builtins.fromJSON (
      builtins.unsafeDiscardStringContext (builtins.toJSON c.services.upstreamer.generatedSettings)
    )
  ) systems;

  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);

  problems =
    lib.concatLists (
      lib.mapAttrsToList (
        name: c:
        let
          seen = observed c;
          fixture = ../../tests/fixtures/config + "/${name}.json";
        in
        lib.optional (seen != expected.${name})
          "${name}: derived ${builtins.toJSON seen}\n  expected ${builtins.toJSON expected.${name}}"
        ++
          lib.optional (!builtins.pathExists fixture || hosts.${name} != lib.importJSON fixture)
            "${name}: the emitted config differs from tests/fixtures/config/${name}.json; run `fixtures` in the dev shell"
        ++ lib.optional (builtins.typeOf c.system.build.toplevel.drvPath != "string") "${name}: no system"
      ) systems
    )
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: case:
        let
          seen = failedAssertions (
            eval (pkgs: pkgs.writeShellScriptBin "upstreamer" "") {
              imports = [ case.module ];
              services.upstreamer.enable = true;
            }
          );
        in
        lib.optional (
          seen != case.messages
        ) "rejected ${name}: failed ${builtins.toJSON seen}\n  expected ${builtins.toJSON case.messages}"
      ) rejected
    );
in
{
  # `hosts` stays readable while the check fails, so `fixtures` can rewrite what it compares.
  module-eval = pkgs.runCommand "module-eval" { passthru = { inherit hosts; }; } (
    if problems == [ ] then
      "touch $out"
    else
      throw ("module-eval:\n" + lib.concatStringsSep "\n" problems)
  );
}
// lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
  module-config = pkgs.linkFarm "module-config" (
    lib.mapAttrsToList (name: file: {
      name = "${name}.json";
      path = (eval (_: package) file).services.upstreamer.configFile;
    }) files
  );
}
