{ crane, fenix, ... }:
{
  perSystem =
    { pkgs, lib, ... }:
    let
      toolchain = import ./toolchain.nix { inherit fenix pkgs; };
      craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
      root = ../.;

      # The crate only: bench/ holds its own projects.
      cargoFiles = [
        ../Cargo.toml
        ../Cargo.lock
        ../src
        ../benches
        ../examples/bench-backend.rs
      ];

      args = {
        src = lib.fileset.toSource {
          inherit root;
          fileset = lib.fileset.unions (cargoFiles ++ [ ../tests ]);
        };
        strictDeps = true;
      };

      # The dependency build sees upstreamer itself at version 0.0.0: the manifest loses its
      # version and the lockfile's own entry is rewritten to match. Without this every version
      # bump would rebuild every dependency instead of fetching them from the binary cache.
      ownVersion = (lib.importTOML ../Cargo.toml).package.version;
      depsLock =
        let
          lock = builtins.unsafeDiscardStringContext (builtins.readFile ../Cargo.lock);
          entry = version: "name = \"upstreamer\"\nversion = \"${version}\"\n";
        in
        assert lib.hasInfix (entry ownVersion) lock;
        builtins.toFile "Cargo.lock" (
          builtins.replaceStrings [ (entry ownVersion) ] [ (entry "0.0.0") ] lock
        );
      # RUSTFLAGS reach the dependencies too, so profile-guided builds instrument and optimise
      # them along with upstreamer itself.
      depsWith =
        rustflags:
        craneLib.buildDepsOnly (
          removeAttrs args [ "src" ]
          // lib.optionalAttrs (rustflags != null) { RUSTFLAGS = rustflags; }
          // {
            pname = "upstreamer";
            version = "0.0.0";
            dummySrc = craneLib.mkDummySrc {
              # Without Cargo.lock, which depsLock stands in for.
              src = lib.fileset.toSource {
                inherit root;
                fileset = lib.fileset.difference (lib.fileset.unions cargoFiles) ../Cargo.lock;
              };
              cargoLock = depsLock;
              cleanCargoTomlFilter =
                path: lib.concatStringsSep "." path != "package.version" && craneLib.filters.cargoTomlDefault path;
            };
            cargoVendorDir = craneLib.vendorCargoDeps { inherit (args) src; };
          }
        );

      cargoArtifacts = depsWith null;

      packageWith =
        rustflags:
        craneLib.buildPackage (
          args
          // lib.optionalAttrs (rustflags != null) { RUSTFLAGS = rustflags; }
          // {
            cargoArtifacts = depsWith rustflags;
            # checks.upstreamer-test runs the tests.
            doCheck = false;
            meta = {
              description = "A reverse proxy and static file server for NixOS hosts";
              license = lib.licenses.mit;
              mainProgram = "upstreamer";
            };
          }
        );

      # Linux builds are profile-guided (nix/pgo.nix). The instrumented build writes its counters
      # where LLVM_PROFILE_FILE says when the training runs.
      profile = import ./pgo.nix {
        inherit pkgs craneLib;
        inherit (toolchain) llvm-tools;
        instrumented = packageWith "-Cprofile-generate=/build/pgo";
      };
      upstreamer =
        if pkgs.stdenv.hostPlatform.isLinux then
          packageWith "-Cprofile-use=${profile}"
        else
          packageWith null;
    in
    {
      packages = {
        inherit upstreamer;
        default = upstreamer;
      };

      checks = {
        inherit upstreamer;
        upstreamer-test = craneLib.cargoTest (args // { inherit cargoArtifacts; });
        upstreamer-clippy = craneLib.cargoClippy (
          args
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );
        upstreamer-fmt = craneLib.cargoFmt { inherit (args) src; };
      };
    };
}
