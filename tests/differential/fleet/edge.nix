# The fleet host that runs heimdall and the binary cache with its S3 endpoint. Each block names
# the Caddy site it replaces in ../caddy/edge.Caddyfile.
{
  imports = [ ./heimdall-module.nix ];

  # heimdall.caddy, imported by the heimdall module.
  services.heimdall = {
    enable = true;
    package = {
      type = "derivation";
      name = "heimdall";
      outPath = "@heimdall@";
      web = {
        type = "derivation";
        name = "heimdall-web";
        outPath = "@heimdall-web@";
      };
    };
    virtualHost = "app.example.com";
  };

  # `@cacheBucket path /bucket /bucket/*` proxied with a 300s response header timeout; the
  # signed Host, path and query go upstream unchanged.
  services.upstreamer.virtualHosts."s3.cache.example.com".routes = [
    {
      when.path = [
        "/bucket"
        "/bucket/*"
      ];
      proxy = {
        to = "http://storage:9000";
        timeouts.responseHeader = "300s";
      };
    }
    {
      respond = {
        status = 404;
        body = "Not found";
      };
    }
  ];

  # `@reads { method GET HEAD; not path /api/* }` with a 15s response header timeout, the rest
  # with 60s.
  services.upstreamer.virtualHosts."cache.example.com".routes = [
    {
      when = {
        method = [
          "GET"
          "HEAD"
        ];
        none = [ { path = "/api/*"; } ];
      };
      proxy = {
        to = "http://127.0.0.1:25915";
        timeouts.responseHeader = "15s";
      };
    }
    {
      proxy = {
        to = "http://127.0.0.1:25915";
        timeouts.responseHeader = "60s";
      };
    }
  ];
}
