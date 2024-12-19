(lang dune 2.8)

(name jose)

(license MIT)

(source
 (github ulrikstrid/ocaml-jose))

(homepage https://ulrikstrid.github.io/ocaml-jose)

(documentation https://ulrikstrid.github.io/ocaml-jose)

(authors "Ulrik Strid")

(maintainers
 "Ulrik Strid <ulrik.strid@outlook.com>"
 "Antonio Nuno Monteiro <anmonteiro@gmail.com>")

(generate_opam_files true)

(package
 (name jose)
 (synopsis "JOSE implementation for OCaml and ReasonML")
 (description
  "JavaScript Object Signing and Encryption built ontop of pure OCaml libs")
 (depends
  (ocaml
   (>= 4.08.0))
  (base64
   (>= 3.3.0))
  dune
  (eqaf
   (>= 0.7))
  (mirage-crypto
   (>= 1.0.0))
  (x509
   (>= 0.13.0))
  astring
  (yojson
   (>= 1.6.0))
  zarith
  ptime
  (mirage-crypto-rng
   (and
    :with-test
    (>= 1.0.0)))
  digestif
  (containers :with-test)
  (bisect_ppx :with-test)
  (alcotest :with-test)
  (junit :with-test)
  (junit_alcotest :with-test)))
