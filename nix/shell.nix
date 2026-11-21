{ fenix, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      toolchain = import ./toolchain.nix { inherit fenix pkgs; };
      # cargo-fuzz needs a nightly compiler (-Zsanitizer, sancov). The fenix input pins which
      # nightly; the stable toolchain above stays the default everywhere else.
      nightly = fenix.packages.${system}.latest.withComponents [
        "cargo"
        "rustc"
        "rust-src"
        "rust-std"
        "llvm-tools-preview"
      ];
    in
    {
      devshells.default = {
        motd = "";
        packages = [
          toolchain
          pkgs.jq
        ];
        commands = [
          {
            name = "fixtures";
            help = "rewrite tests/fixtures/config from the example hosts in nix/examples";
            # checks.module-eval fails while a fixture differs from what the module emits.
            command = ''
              set -eu
              cd "$PRJ_ROOT"
              for host in $(nix eval --raw ".#checks.${system}.module-eval.hosts" --apply 'hs: toString (builtins.attrNames hs)'); do
                nix eval --json ".#checks.${system}.module-eval.hosts.$host" | jq --sort-keys . > "tests/fixtures/config/$host.json"
              done
            '';
          }
        ];
      };

      # `nix develop .#fuzz`: the nightly toolchain and cargo-fuzz, for fuzz/ (see
      # fuzz/README.md).
      devshells.fuzz = {
        motd = "";
        packages = [
          nightly
          pkgs.cargo-fuzz
        ];
      };
    };
}
