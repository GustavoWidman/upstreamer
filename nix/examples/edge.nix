# An app contributed by a third-party module, and a binary cache with its S3 endpoint. Every
# host is TLS with an ACME certificate named after it, by default.
{
  imports = [ ./app-module.nix ];

  services.example-app = {
    enable = true;
    virtualHost = "app.example.com";
  };

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

  # Access logs: one host in the service's logs directory, one in a directory of its own.
  services.upstreamer.virtualHosts."cache.example.com".accessLog.enable = true;
  services.upstreamer.virtualHosts."s3.cache.example.com".accessLog = {
    enable = true;
    path = "/srv/logs/s3.log";
  };
}
