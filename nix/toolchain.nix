# The toolchain pinned in rust-toolchain.toml, shared by the package and the dev shell.
{ fenix, pkgs }:
fenix.packages.${pkgs.stdenv.hostPlatform.system}.fromToolchainFile {
  file = ../rust-toolchain.toml;
  sha256 = "sha256-MFHoWVcPZKjFrLnQnodCXbUsfZcofGfo9tV9fTTvklg=";
}
