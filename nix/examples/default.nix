# Checks of the NixOS module on the example hosts.
#
# module-eval evaluates them, without building anything, and checks what the module derives
# from their virtual hosts: the config it emits (equal to tests/fixtures/config, which the Rust
# schema tests read), the ACME certificates and their names and groups, the unit, the firewall
# and the kernel modules. Each host's whole system is instantiated too, so a type error anywhere
# in the module fails here. The hosts get a stub package, so evaluating them for another system
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
      failedAssertions = map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);
      certs = lib.mapAttrs (_: cert: {
        inherit (cert) domain group;
        extraDomainNames = sorted cert.extraDomainNames;
        reloadServices = sorted cert.reloadServices;
      }) c.security.acme.certs;
      unit = {
        inherit (u.serviceConfig) Type ExecStart;
        SupplementaryGroups = sorted u.serviceConfig.SupplementaryGroups;
        wants = sorted u.wants;
      };
      tcp = sorted c.networking.firewall.allowedTCPPorts;
      udp = sorted c.networking.firewall.allowedUDPPorts;
      tlsModule = lib.elem "tls" c.boot.kernelModules;
    };

  cert = domain: extraDomainNames: group: reloadServices: {
    inherit
      domain
      extraDomainNames
      group
      reloadServices
      ;
  };
  own = domain: cert domain [ ] "upstreamer" [ "upstreamer.service" ];
  unit = groups: certs: {
    Type = "notify-reload";
    ExecStart = "${lib.getExe systems.edge.services.upstreamer.package} run --config /etc/upstreamer/config.json";
    SupplementaryGroups = groups;
    wants = map (c: "acme-${c}.service") certs;
  };

  expected = {
    edge = {
      failedAssertions = [ ];
      certs = lib.genAttrs [ "app.example.com" "cache.example.com" "s3.cache.example.com" ] own;
      unit = unit [ "upstreamer" ] [ "app.example.com" "cache.example.com" "s3.cache.example.com" ];
      tcp = [
        80
        443
      ];
      udp = [ 443 ];
      tlsModule = true;
    };
    apps = {
      failedAssertions = [ ];
      certs = lib.genAttrs [ "files.example.net" "play.example.net" "relay.example.net" ] own // {
        "dns.example.net" = cert "dns.example.net" [ ] "dns-certs" [
          "dns-server.service"
          "upstreamer.service"
        ];
        "mail.example.net" = cert "mail.example.net" [ ] "mail-certs" [ "upstreamer.service" ];
        "example.org" = cert "example.org" [ "blog.example.org" "www.example.org" ] "upstreamer" [
          "upstreamer.service"
        ];
      };
      unit =
        unit
          [ "dns-certs" "mail-certs" "upstreamer" ]
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
    };
    desktop = {
      failedAssertions = [ ];
      certs = { };
      unit = unit [ ] [ ];
      tcp = [ ];
      udp = [ ];
      tlsModule = false;
    };
  };

  # The emitted config, as JSON would carry it.
  hosts = lib.mapAttrs (
    _: c:
    builtins.fromJSON (
      builtins.unsafeDiscardStringContext (builtins.toJSON c.services.upstreamer.generatedSettings)
    )
  ) systems;

  problems = lib.concatLists (
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
