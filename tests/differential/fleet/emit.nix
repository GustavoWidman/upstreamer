# The config the NixOS module emits for a fleet host, as JSON: the upstreamer side of the
# differential tests. After changing the module or a host here, rewrite the emitted files from
# the repository root:
#
#   for host in edge apps desktop; do
#     nix eval --impure --json --expr "import ./tests/differential/fleet/emit.nix { host = \"$host\"; }" \
#       | jq --sort-keys . > "tests/differential/fleet/$host.json"
#   done
{
  host,
  flake ? builtins.getFlake "git+file://${toString ../../..}",
}:
let
  system = flake.inputs.nixpkgs.lib.nixosSystem {
    modules = [
      flake.nixosModules.default
      ./common.nix
      (./. + "/${host}.nix")
    ];
  };
  settings = system.config.services.upstreamer.generatedSettings;
in
builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.toJSON settings))
