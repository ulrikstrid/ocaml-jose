{
  description = "my project description";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:anmonteiro/nix-overlays/ulrikstrid/odoc-2_1_0";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
        devShell = pkgs.callPackage ./shell.nix { };
      in
      {
        inherit devShell;
      }
    );
}
