# A blog with Prometheus metrics. `metrics.enable` adds a site on its own loopback listener: its
# port is one the proxy listens on, so it reaches `upstreamer check --expect-tcp`, and it stays
# out of the firewall.
{
  services.upstreamer = {
    enable = true;

    metrics = {
      enable = true;
      listen = [ "127.0.0.1:9100" ];
    };

    virtualHosts."blog.example.com".routes = [
      {
        name = "api";
        when.path = "/api/*";
        proxy = "http://127.0.0.1:4000";
      }
      {
        name = "static";
        files.root = "/srv/blog";
      }
    ];
  };
}
