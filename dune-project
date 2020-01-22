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
   (ocaml (>= 4.06.0))
   base64
   (dune (and (>= 1.11) (< 2.0)))
   nocrypto
   (x509 ( >= 0.8.0))
   astring
   yojson
   zarith
   (containers :with-test)
   (bisect_ppx :with-test)
   (reason :with-test)
   (rely :with-test)
   (lwt :with-test))
)
