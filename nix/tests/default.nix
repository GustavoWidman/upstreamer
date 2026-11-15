# NixOS VM tests: each boots services.upstreamer with the real package and checks what a host
# serves. They need KVM; build one with `nix build .#checks.x86_64-linux.vm-<name>`.
#
# - vm-acme: certificates from a test ACME server (pebble, DNS-01): the answer before the first
#   issuance, the switch to the issued chain, renewal under a live keep-alive connection, and a
#   failed issuance next to a working one.
# - vm-proxy: h1, h2 and h3 from another machine through the firewall, the HTTPS redirect, a
#   WebSocket, a config switch that reloads under load, and the unit's sandbox.
# - vm-heimdall: heimdall's virtual host (its NixOS module's routes) over a fixture web build and
#   a stub API.
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
        vm-proxy = test ./proxy.nix;
        vm-heimdall = test ./heimdall.nix;
      };
    };
}
