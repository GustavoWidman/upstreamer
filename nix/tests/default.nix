# NixOS VM tests: each boots services.upstreamer with the real package and checks what a host
# serves. They need KVM; build one with `nix build .#checks.x86_64-linux.vm-<name>`.
#
# - vm-acme: certificates from a test ACME server (pebble, DNS-01): the answer before the first
#   issuance, the switch to the issued chain, renewal under a live keep-alive connection, and a
#   failed issuance next to a working one.
# - vm-acme-inprocess: certificates the proxy orders itself (`tls.acme`) from pebble over HTTP-01
#   and TLS-ALPN-01: the retry after an unreachable CA, the issued chains served without a
#   restart, private state files, renewal in the same process, and a restart from stored files.
# - vm-proxy: h1, h2 and h3 from another machine through the firewall, the HTTPS redirect, a
#   WebSocket, a config switch that reloads under load, and the unit's sandbox.
# - vm-heimdall: heimdall's virtual host (its NixOS module's routes) over a fixture web build and
#   a stub API.
# - vm-upgrade: a switch to another package under h1, h2 and h3 load (the new program takes the
#   sockets over: nothing refused, no request failed, the unit active with a new main process),
#   a stop during the handover, a config-only switch, a unit change, and a package that cannot
#   run.
{ self, ... }:
{
  perSystem =
    { pkgs, lib, ... }:
    let
      args = {
        inherit pkgs lib;
        module = self.nixosModules.default;
        tls = import ./tls.nix { inherit pkgs; };
      };
      test = file: pkgs.testers.runNixOSTest (import file args);
    in
    {
      checks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        vm-acme = test ./acme.nix;
        vm-acme-inprocess = test ./acme-inprocess.nix;
        vm-proxy = test ./proxy.nix;
        vm-heimdall = test ./heimdall.nix;
        vm-upgrade = test ./upgrade.nix;
      };
    };
}
