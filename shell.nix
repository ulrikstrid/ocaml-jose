{ pkgs }:
let
  inherit (pkgs) lib;
  josePkgs = pkgs.recurseIntoAttrs (import ./nix { inherit pkgs; doCheck = true; }).native;
  joseDrvs = lib.filterAttrs (_: value: lib.isDerivation value) josePkgs;

  filterDrvs = inputs:
    lib.filter
      (drv:
        # we wanna filter our own packages so we don't build them when entering
        # the shell. They always have `pname`
        !(lib.hasAttr "pname" drv) ||
        drv.pname == null ||
        !(lib.any (name: name == drv.pname || name == drv.name) (lib.attrNames joseDrvs)))
      inputs;
in
with pkgs;

(mkShell {
  inputsFrom = lib.attrValues joseDrvs;
  buildInputs = with ocamlPackages; [
    merlin
    ocaml-lsp
    ocamlformat
    dune-release
    cacert
    curl
    gnupg
    odoc
  ];
}).overrideAttrs (o: {
  propagatedBuildInputs = filterDrvs o.propagatedBuildInputs;
  buildInputs = filterDrvs o.buildInputs;
  checkInputs = filterDrvs o.checkInputs;
})
