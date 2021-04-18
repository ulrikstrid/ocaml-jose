let
  pkgs = import ./nix/sources.nix { };
  inherit (pkgs) lib;
  oidcPkgs = pkgs.recurseIntoAttrs (import ./nix { inherit pkgs; }).native;
  logsPpxDrvs = lib.filterAttrs (_: value: lib.isDerivation value) oidcPkgs;

  filterDrvs = inputs:
    lib.filter
      (drv:
        # we wanna filter our own packages so we don't build them when entering
        # the shell. They always have `pname`
        !(lib.hasAttr "pname" drv) ||
        drv.pname == null ||
        !(lib.any (name: name == drv.pname || name == drv.name) (lib.attrNames logsPpxDrvs)))
      inputs;
in
with pkgs;

(mkShell {
  inputsFrom = lib.attrValues logsPpxDrvs;
  buildInputs = with ocamlPackages; [
    merlin
    ocaml-lsp
    ocamlformat
    dune-release
    cacert
    curl
    git
  ];
}).overrideAttrs (o: {
  propagatedBuildInputs = filterDrvs o.propagatedBuildInputs;
  buildInputs = filterDrvs o.buildInputs;
})
