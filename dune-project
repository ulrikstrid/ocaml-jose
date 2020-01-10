(lang dune 1.11)
(name jose)
(source (github ulrikstrid/reason-jose))
(homepage https://ulrikstrid.github.io/reason-jose)
(documentation https://ulrikstrid.github.io/reason-jose)
(generate_opam_files true)

(using fmt 1.2)

(package
 (name jose)
 (synopsis "JOSE implementation for OCaml and ReasonML")
 (depends
   (ocaml (>= 4.06.0))
   base64
   containers
   (dune (>= 1.11))
   hex
   nocrypto
   x509
   ppx_deriving_yojson)
)
