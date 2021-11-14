{
  description = "my project description";

  inputs.ocaml-overlay.url = "github:anmonteiro/nix-overlays/ulrikstrid/flakify";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:nixos/nixpkgs";

  outputs = { self, nixpkgs, ocaml-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ ocaml-overlay.overlay ]; };
        devShell = import ./shell.nix {
          inherit pkgs;
        };
      in
      {
        inherit devShell;
      }
    );
}
