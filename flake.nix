{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }: flake-utils.lib.eachDefaultSystem (system: 
    let
      pkgs = import nixpkgs {
        inherit system;
      };
      cjks = pkgs.stdenv.mkDerivation {
          name = "cjks";
          src = ./.;
          nativeBuildInputs = [
            pkgs.clang
            pkgs.cmake
          ];
          buildInputs = [
            pkgs.openssl
          ];
        };
    in {
      packages = {
        default = cjks;
      };
      devShells = {
        default = pkgs.mkShell {
          inputsFrom = [cjks];
        };
      };
    }
  );
}
