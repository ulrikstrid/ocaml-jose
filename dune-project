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
 (depends
   (ocaml (>= 4.06.0))
   base64
   (dune (>= 1.11))
   nocrypto
   (x509 ( >= 0.8.0))
   astring
   (containers :with-test)
   (bisect_ppx :with-test)
   (reason :with-test)
   (rely :with-test)
   (lwt :with-test))
)
