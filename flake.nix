{
  description = "my project description";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.inputs.flake-utils.follows = "flake-utils";
    nixpkgs.url = "github:anmonteiro/nix-overlays";

    nix-filter.url = "github:numtide/nix-filter";
  };

  outputs = { self, nixpkgs, flake-utils, nix-filter }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
        devShell = pkgs.callPackage ./shell.nix { inherit nix-filter; };
      in
      {
        inherit devShell;
      }
    );
}
