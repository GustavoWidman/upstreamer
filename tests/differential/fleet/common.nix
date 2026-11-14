# What every fleet host shares: a container (no bootloader or file systems to declare), the
# lego defaults a host keeps for itself, and a stub package, since only the emitted config is
# read.
{ pkgs, ... }:
{
  boot.isContainer = true;
  system.stateVersion = "26.05";
  nixpkgs.hostPlatform = "aarch64-linux";
  services.upstreamer.package = pkgs.writeShellScriptBin "upstreamer" "";

  security.acme = {
    acceptTerms = true;
    defaults = {
      email = "admin@example.com";
      dnsProvider = "cloudflare";
      environmentFile = "/run/secrets/acme.env";
    };
  };
}
