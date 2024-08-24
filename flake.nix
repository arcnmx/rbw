{
  description = "Bitwarden CLI";
  inputs = {
    flakelib.url = "github:flakelib/fl";
    nixpkgs = { };
    rust = {
      url = "github:arcnmx/nixexprs-rust";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { flakelib, self, nixpkgs, rust, ... }@inputs: let
    nixlib = nixpkgs.lib;
    inherit (nixlib)
      optional
    ;
  in flakelib {
    inherit inputs;
    config = {
      name = "bitw";
    };
    packages = {
      rbw = {
        __functor = _: import ./derivation.nix;
        fl'config.args = {
          crate.fallback = self.lib.crate;
        };
      };
      default = { rbw }: rbw;
    };
    overlays = {
      rbw-bitw = final: prev: {
        rbw-bitw = final.callPackage ./derivation.nix {
          inherit (self.lib) crate;
        };
      };
      default = self.overlays.rbw-bitw;
    };
    checks = {
      test = { rustPlatform, source, rbw }: rustPlatform.buildRustPackage {
        pname = self.lib.crate.package.name;
        inherit (self.lib.crate) cargoLock version;
        inherit (rbw) buildInputs nativeBuildInputs;
        src = source;
        buildType = "debug";
        meta.name = "cargo test";
      };
    };
    devShells = {
      plain = {
        mkShell, writeShellScriptBin, hostPlatform, lib
      , enableRust ? true, cargo
      , rustTools ? [ ]
      , rbw, pkg-config
      }: mkShell {
        RUST_LOG = "rbw=debug";
        allowBroken = true;
        inherit rustTools;
        inherit (rbw) buildInputs;
        nativeBuildInputs = optional hostPlatform.isUnix pkg-config ++ optional enableRust cargo ++ [
          (writeShellScriptBin "generate" ''nix run .#generate "$@"'')
        ];
      };
      stable = { rust'stable, outputs'devShells'plain }: outputs'devShells'plain.override {
        inherit (rust'stable) mkShell;
        enableRust = false;
      };
      dev = { rust'unstable, outputs'devShells'plain }: outputs'devShells'plain.override {
        inherit (rust'unstable) mkShell;
        enableRust = false;
        rustTools = [ "rust-analyzer" ];
      };
      default = { outputs'devShells }: outputs'devShells.plain;
    };
    legacyPackages = {
      source = { rust'builders }: rust'builders.wrapSource self.lib.crate.src;

      generate = { rust'builders, outputHashes }: rust'builders.generateFiles {
        paths = {
          "lock.nix" = outputHashes;
        };
      };
      outputHashes = { rust'builders }: rust'builders.cargoOutputHashes {
        inherit (self.lib) crate;
      };
    };
    lib = {
      crate = rust.lib.importCargo {
        path = ./Cargo.toml;
        inherit (import ./lock.nix) outputHashes;
      };
      inherit (self.lib.crate.package) version;
    };
  };
}
