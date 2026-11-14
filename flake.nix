{
  description = "upstreamer: a reverse proxy and static file server for NixOS hosts";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-parts.url = "github:hercules-ci/flake-parts";
    devshell.url = "github:numtide/devshell";
    # The benchmark's load generators and competing proxies, held at the revision the stored
    # competitor medians were measured with; moving it means refreshing those medians.
    nixpkgs-bench.url = "github:nixos/nixpkgs/6368eda62c9775c38ef7f714b2555a741c20c72d";
  };

  outputs =
    inputs@{ flake-parts, devshell, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      imports = [
        devshell.flakeModule
        (import ./nix/shell.nix inputs)
        (import ./nix/package.nix inputs)
        (import ./nix/module.nix inputs)
        (import ./nix/bench.nix inputs)
      ];
    };
}
