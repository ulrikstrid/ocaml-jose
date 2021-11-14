{ ocamlVersion ? "4_12" }:
let
  overlays =
    builtins.fetchTarball
      https://github.com/anmonteiro/nix-overlays/archive/e6b67def144f41bdf22b629f2edb9f7d4f9ac35c.tar.gz;

in

import "${overlays}/boot.nix" {
  overlays = [
    (import overlays)
    (self: super: {
      ocamlPackages = (super.ocaml-ng."ocamlPackages_${ocamlVersion}");

      pkgsCross.musl64.pkgsStatic = super.pkgsCross.musl64.pkgsStatic.appendOverlays [
        (self: super: {
          ocamlPackages = super.ocaml-ng."ocamlPackages_${ocamlVersion}";
        })
      ];
    })
  ];
}
