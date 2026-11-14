# Hosts off the defaults: a contributed app served over plain HTTP on its own port (the shape of
# a VM test), a certificate from files, a wildcard host on its base domain's certificate, a TLS
# host on its own port, and server timeouts and limits (a longer drain on shutdown among them).
{
  imports = [ ./app-module.nix ];

  services.example-app = {
    enable = true;
    virtualHost = "localhost";
  };

  services.upstreamer = {
    settings = {
      timeouts = {
        shutdown = "30s";
        keepAlive = "120s";
      };
      limits.maxHeadBytes = 65536;
    };

    virtualHosts = {
      localhost = {
        tls.enable = false;
        listen = [ { port = 8080; } ];
      };

      "node.tailnet.ts.net" = {
        tls = {
          certFile = "/var/lib/tailscale/certs/node.tailnet.ts.net.crt";
          keyFile = "/var/lib/tailscale/certs/node.tailnet.ts.net.key";
        };
        http3 = false;
        proxy = "http://127.0.0.1:59553";
      };

      "*.preview.example.com" = {
        tls.acmeCert = "preview.example.com";
        proxy = "http://127.0.0.1:4000";
      };

      "admin.example.com" = {
        listen = [ { port = 8443; } ];
        proxy = "http://127.0.0.1:9000";
      };
    };
  };
}
