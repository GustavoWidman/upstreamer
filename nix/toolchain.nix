# The toolchain pinned in rust-toolchain.toml, shared by the package and the dev shell, and the
# LLVM tools of the same release (llvm-profdata for profile-guided builds).
{ fenix, pkgs }:
let
  fenixPkgs = fenix.packages.${pkgs.stdenv.hostPlatform.system};
  file = ../rust-toolchain.toml;
  sha256 = "sha256-MFHoWVcPZKjFrLnQnodCXbUsfZcofGfo9tV9fTTvklg=";
  inherit ((pkgs.lib.importTOML file).toolchain) channel;
in
fenixPkgs.fromToolchainFile { inherit file sha256; }
// {
  llvm-tools = (fenixPkgs.toolchainOf { inherit channel sha256; }).llvm-tools;
}
