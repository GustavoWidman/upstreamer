# A third-party flake's NixOS module for a static site whose build generates its route
# fragments (`upstreamer/main.json`, `upstreamer/blog.json`). The module names them with
# `include` steps; upstreamer reads them at load and `upstreamer check` validates them at build
# time, so Nix never reads the generated files.
{ config, lib, ... }:
let
  cfg = config.services.example-site;
  site = kind: { routes = [ { include = "${cfg.fragments}/${kind}.json"; } ]; };
in
{
  options.services.example-site = {
    enable = lib.mkEnableOption "the example site";
    fragments = lib.mkOption {
      type = lib.types.path;
      description = "Directory holding the generated main.json and blog.json.";
    };
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
