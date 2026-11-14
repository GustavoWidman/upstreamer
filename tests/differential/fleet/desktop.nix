# The fleet's desktop host: a plain-HTTP catch-all that sends / to the noVNC page and proxies
# everything else, its websocket included. It replaces the `http://:80` site of
# ../caddy/desktop.Caddyfile.
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
}
