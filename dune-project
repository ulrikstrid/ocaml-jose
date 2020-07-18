(lang dune 1.11)
(name jose)
(license MIT)
(source (github ulrikstrid/reason-jose))
(homepage https://ulrikstrid.github.io/reason-jose)
(documentation https://ulrikstrid.github.io/reason-jose)
(authors "Ulrik Strid")
(maintainers "ulrik.strid@outlook.com")

(generate_opam_files true)

(using fmt 1.2)

(package
 (name jose)
 (synopsis "JOSE implementation for OCaml and ReasonML")
 (description "JavaScript Object Signing and Encryption built ontop of pure OCaml libs")
 (depends
   (ocaml (>= 4.08.0))
   (base64 (>= 3.0.0))
   (dune (>= 1.11))
   (eqaf (>= 0.7))
   (mirage-crypto (>= 0.8.1))
   (x509 (>= 0.10.0))
   (cstruct (>= 4.0.0))
   astring
   yojson
   result
   zarith
   (containers :with-test)
   (bisect_ppx :with-test)
   (alcotest :with-test)
   (junit :with-test)
   (junit_alcotest :with-test)
   (lwt :with-test))
)
