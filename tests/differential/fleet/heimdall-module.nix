# The heimdall flake's NixOS module, as far as it touches the proxy: the web app from its build
# directory with content-hash ETags and security headers, and /api proxied to the server. It
# replaces `share/heimdall/heimdall.caddy` (../caddy/heimdall.caddy).
{ config, lib, ... }:
let
  cfg = config.services.heimdall;
  web = cfg.package.web;
in
{
  options.services.heimdall = {
    enable = lib.mkEnableOption "heimdall";
    package = lib.mkOption { type = lib.types.package; };
    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:7979";
    };
    virtualHost = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
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
          Permissions-Policy = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
          Cross-Origin-Opener-Policy = "same-origin";
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
                  root = "${web}";
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
                  root = "${web}";
                  paths = [ "{path}" ];
                };
              }
            ];
            rewrite = "/index.html";
          }
          {
            files = {
              root = "${web}";
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
