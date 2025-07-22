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

          cmakeFlags = [
            "-DCJKS_TEST=1"
          ];

          nativeBuildInputs = [
            pkgs.clang
            pkgs.cmake
          ];

          buildInputs = [
            pkgs.openssl
            pkgs.valgrind
          ];

          doCheck = true; # Enable the checkPhase

          checkPhase = ''
            ctest -T memcheck
          '';

          outputs = [
            "out" "dev"
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
      checks = {
        inherit cjks;
      };
    }
  );
}
