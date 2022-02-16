{ pkgs, stdenv, lib, ocamlPackages, static ? false, doCheck }:

with ocamlPackages;

rec {
  jose = buildDunePackage {
    pname = "jose";
    version = "0.2.0-dev";

    src = lib.filterGitSource {
      src = ./..;
      dirs = [ "jose" "test" ];
      files = [ "dune-project" "jose.opam" ];
    };

    useDune2 = true;

    checkInputs = [
      containers
      bisect_ppx
      alcotest
      junit
      junit_alcotest
      lwt
    ];

    propagatedBuildInputs = [
      base64
      eqaf
      mirage-crypto
      mirage-crypto-pk
      mirage-crypto-ec
      x509
      cstruct
      astring
      yojson
      zarith
      ppxlib # needed by bisect_ppx
      pkgs.gmp
    ];

    inherit doCheck;

    meta = {
      description = "Base functions and types to work with OpenID Connect.";
      # license = stdenv.lib.licenses.bsd3;
    };
  };
}
