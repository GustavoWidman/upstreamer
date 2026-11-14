# What every example host shares: a container (no bootloader or file systems to declare) with
# the lego defaults a host keeps for itself.
{
  boot.isContainer = true;
  system.stateVersion = "26.05";

  security.acme = {
    acceptTerms = true;
    defaults = {
      email = "admin@example.com";
      dnsProvider = "cloudflare";
      environmentFile = "/run/secrets/acme.env";
    };
  };
}
