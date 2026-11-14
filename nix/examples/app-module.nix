# A third-party flake's NixOS module that contributes a virtual host: it serves its web app's
# files and proxies its API, while the host that enables it only names the virtual host (and
# may set its TLS there).
{ config, lib, ... }:
let
  cfg = config.services.example-app;
in
{
  options.services.example-app = {
    enable = lib.mkEnableOption "the example app";
    virtualHost = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:7979";
    };
    webRoot = lib.mkOption {
      type = lib.types.str;
      default = "/srv/example-app/web";
    };
  };

  config = lib.mkIf (cfg.enable && cfg.virtualHost != null) {
    services.upstreamer = {
      enable = lib.mkDefault true;
      virtualHosts.${cfg.virtualHost} = {
        headers = {
          Server = null;
          X-Content-Type-Options = "nosniff";
          X-Frame-Options = "DENY";
          Referrer-Policy = "no-referrer";
        };
        routes = [
          {
            name = "api";
            when.path = "/api/*";
            proxy = "http://${cfg.listen}";
          }
          {
            name = "immutable";
            when.path = "/_app/immutable/*";
            routes = [
              { headers.Cache-Control = "public, max-age=31536000, immutable"; }
              {
                files = {
                  root = cfg.webRoot;
                  precompressed = [
                    "br"
                    "gzip"
                  ];
                };
              }
            ];
          }
          {
            headers = {
              Cache-Control = "no-cache";
              Last-Modified = null;
            };
          }
          { requestHeaders.If-Modified-Since = null; }
          {
            name = "sidecar";
            when.path = [
              "*.etag"
              "*.br"
              "*.gz"
            ];
            error = 404;
          }
          {
            name = "client-route";
            when.none = [
              { path = "/_app/*"; }
              {
                file = {
                  root = cfg.webRoot;
                  paths = [ "{path}" ];
                };
              }
            ];
            rewrite = "/index.html";
          }
          {
            files = {
              root = cfg.webRoot;
              precompressed = [
                "br"
                "gzip"
              ];
              etagSidecar = ".etag";
            };
          }
        ];
      };
    };
  };
}
