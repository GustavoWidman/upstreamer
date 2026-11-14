# A plain-HTTP catch-all bound on the wildcard address, so it starts before any interface has an
# address, and opened on one interface only.
{
  services.upstreamer = {
    enable = true;
    openFirewall = false;
    virtualHosts.desktop = {
      serverName = "*";
      tls.enable = false;
      routes = [
        {
          when.path = "/";
          redirect = {
            to = "/vnc.html?autoconnect=1&resize=scale";
            status = 302;
          };
        }
        { proxy = "http://127.0.0.1:6080"; }
      ];
    };
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ 80 ];
}
