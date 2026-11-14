# Benchmark toolchain: the origin, every load generator and every competing
# proxy, pinned by the flake's nixpkgs-bench input. `nix run .#bench -- <command>` runs
# the harness in bench/harness with BENCH_TOOLS pointing at a JSON manifest of
# store paths and versions, so each result records exactly what it ran.
{ nixpkgs-bench, ... }:
{ lib, ... }:
{
  perSystem =
    { system, ... }:
    let
      pkgs = import nixpkgs-bench { inherit system; };
      origin = pkgs.rustPlatform.buildRustPackage {
        pname = "bench-origin";
        version = "0.1.0";
        src = ../bench/origin;
        cargoLock.lockFile = ../bench/origin/Cargo.lock;
      };

      harness = lib.fileset.toSource {
        root = ../bench;
        fileset = lib.fileset.unions [
          ../bench/harness
          ../bench/servers
        ];
      };

      h2load = pkgs.nghttp2.override { enableHttp3 = true; };

      # The pinned nixpkgs carries a traefik early-access build; benchmark the
      # vendor's current stable release binary instead.
      traefik = pkgs.stdenvNoCC.mkDerivation rec {
        pname = "traefik-bin";
        version = "3.7.19";
        src = pkgs.fetchurl {
          url = "https://github.com/traefik/traefik/releases/download/v${version}/traefik_v${version}_linux_amd64.tar.gz";
          sha256 = "1gl95yhsiwhhnpjwfk8i22n1d0kwwgpyrbgjs0vp222s6dl4llwp";
        };
        sourceRoot = ".";
        installPhase = "install -Dm755 traefik $out/bin/traefik";
        meta.platforms = [ "x86_64-linux" ];
      };

      servers = {
        nginx = pkgs.nginxMainline;
        haproxy = pkgs.haproxy;
        caddy = pkgs.caddy;
        envoy = pkgs.envoy-bin;
        inherit traefik;
        h2o = pkgs.h2o;
        httpd = pkgs.apacheHttpd;
        sozu = pkgs.sozu;
        ferron = pkgs.ferron;
        lighttpd = pkgs.lighttpd;
      };

      tools = servers // {
        inherit origin h2load;
        inherit (pkgs)
          wrk
          wrk2
          oha
          openssl
          perf
          inferno
          python3
          rustc
          cargo
          ;
      };

      manifest = pkgs.writeText "bench-tools.json" (
        builtins.toJSON (
          lib.mapAttrs (_: pkg: {
            path = "${pkg}";
            bin = "${lib.getBin pkg}/bin";
            version = pkg.version or "unknown";
          }) tools
        )
      );

      bench = pkgs.writeShellApplication {
        name = "bench";
        runtimeInputs = with pkgs; [
          python3
          rustc
          cargo
          gcc
          gnumake
          pkg-config
          util-linux
          procps
          git
          curl
        ];
        text = ''
          export BENCH_TOOLS=${manifest}
          export PYTHONPATH=${harness}''${PYTHONPATH:+:$PYTHONPATH}
          exec python3 -m harness "$@"
        '';
      };
    in
    lib.mkIf (system == "x86_64-linux") {
      packages = {
        bench-origin = origin;
        bench-h2load = h2load;
        inherit bench;
      };

      apps.bench = {
        type = "app";
        program = lib.getExe bench;
      };

      devShells.bench = pkgs.mkShell {
        packages = [
          bench
          origin
          h2load
          pkgs.curl
          pkgs.wrk
          pkgs.wrk2
          pkgs.oha
          pkgs.openssl
          pkgs.perf
          pkgs.inferno
        ]
        ++ builtins.attrValues servers;
        BENCH_TOOLS = manifest;
      };
    };
}
