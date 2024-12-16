{
  pkgs,
  stdenv,
  lib,
  nix-filter,
  ocamlPackages,
  static ? false,
  doCheck,
}:
with ocamlPackages; rec {
  jose = buildDunePackage {
    pname = "jose";
    version = "0.2.0-dev";

    src = with nix-filter.lib;
      filter {
        root = ./..;
        # If no include is passed, it will include all the paths.
        include = [
          # Include the "src" path relative to the root.
          "jose"
          "test"
          # Include this specific path. The path must be under the root.
          ../jose.opam
          ../dune-project
          # Include all files with the .ml extension
          (matchExt "ml")
        ];
      };

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
      astring
      yojson
      zarith
      ptime
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
