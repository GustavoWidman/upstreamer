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
          # `upstreamer example` embeds the example configs; a test holds docs/config.md to
          # the schema.
          fileset = lib.fileset.unions (
            cargoFiles
            ++ [
              ../tests
              (lib.fileset.fileFilter (file: file.hasExt "toml") ../examples)
              ../docs/config.md
            ]
          );
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
      #
      # `extra` selects a variant: cargoExtraArgs with the cargo features it builds.
      depsWith =
        extra: rustflags:
        craneLib.buildDepsOnly (
          removeAttrs args [ "src" ]
          // extra
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

      cargoArtifacts = depsWith { } null;

      packageWith =
        extra: rustflags:
        craneLib.buildPackage (
          args
          // extra
          // lib.optionalAttrs (rustflags != null) { RUSTFLAGS = rustflags; }
          // {
            cargoArtifacts = depsWith extra rustflags;
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
      # where LLVM_PROFILE_FILE says when the training runs. Each variant trains its own profile.
      variant =
        extra:
        let
          profile = import ./pgo.nix {
            inherit pkgs craneLib;
            inherit (toolchain) llvm-tools;
            instrumented = packageWith extra "-Cprofile-generate=/build/pgo";
          };
        in
        if pkgs.stdenv.hostPlatform.isLinux then
          packageWith extra "-Cprofile-use=${profile}"
        else
          packageWith extra null;
      upstreamer = variant { };

      # Origins from Kubernetes EndpointSlices (`proxy.to.kubernetes`): the default build with
      # the `kubernetes` cargo feature, which adds the discovery thread and its API client.
      kubernetesArgs = {
        cargoExtraArgs = "--locked --features kubernetes";
      };
      kubernetes = variant kubernetesArgs;
    in
    {
      packages = {
        inherit upstreamer kubernetes;
        default = upstreamer;
      }
      // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        # The `kubernetes` variant as a container image: tests/kubernetes runs it as a pod.
        kubernetes-image = pkgs.dockerTools.buildLayeredImage {
          name = "upstreamer";
          tag = "kubernetes";
          compressor = "none";
          config.Entrypoint = [ (lib.getExe kubernetes) ];
        };
      };

      checks = {
        inherit upstreamer kubernetes;
        upstreamer-test = craneLib.cargoTest (args // { inherit cargoArtifacts; });
        upstreamer-clippy = craneLib.cargoClippy (
          args
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );
        upstreamer-test-kubernetes = craneLib.cargoTest (
          args
          // kubernetesArgs
          // {
            cargoArtifacts = depsWith kubernetesArgs null;
          }
        );
        upstreamer-clippy-kubernetes = craneLib.cargoClippy (
          args
          // {
            cargoArtifacts = depsWith kubernetesArgs null;
            cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
          }
        );
        upstreamer-fmt = craneLib.cargoFmt { inherit (args) src; };
      };
    };
}
