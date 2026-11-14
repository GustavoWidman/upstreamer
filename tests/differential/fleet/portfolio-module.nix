# The portfolio flake's NixOS module: each host names the route fragment its build generates
# (`upstreamer/main.json` or `upstreamer/blog.json`, ../trees/portfolio/upstreamer), which
# replaces `caddy/portfolio.caddy` in the same build.
{ config, lib, ... }:
let
  cfg = config.services.portfolio;
  site = kind: { routes = [ { include = "${cfg.package}/upstreamer/${kind}.json"; } ]; };
in
{
  options.services.portfolio = {
    enable = lib.mkEnableOption "the portfolio site";
    package = lib.mkOption { type = lib.types.package; };
    domains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
    blogDomains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
  };

  config = lib.mkIf cfg.enable {
    services.upstreamer = {
      enable = lib.mkDefault true;
      virtualHosts =
        lib.genAttrs cfg.domains (_: site "main") // lib.genAttrs cfg.blogDomains (_: site "blog");
    };
  };
}
