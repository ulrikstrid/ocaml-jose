{
  description = "JOSE implementation in OCaml";

  nixConfig = {
    extra-substituters = "https://anmonteiro.nix-cache.workers.dev";
    extra-trusted-public-keys = "ocaml.nix-cache.com-1:/xI2h2+56rwFfKyyFVbkJSeGqSIYMC/Je+7XXqGKDIY=";
  };

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.inputs.flake-utils.follows = "flake-utils";
    nixpkgs.url = "github:nix-ocaml/nix-overlays";

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
