{ pkgs, nix-filter, doCheck ? false }:

{
  native = pkgs.callPackage ./generic.nix {
    inherit doCheck nix-filter;
  };

  musl64 =
    let
      pkgsCross = pkgs.pkgsCross.musl64.pkgsStatic;

    in
    pkgsCross.callPackage ./generic.nix {
      static = true;
      inherit doCheck nix-filter;
      ocamlPackages = pkgsCross.ocamlPackages;
    };
}
