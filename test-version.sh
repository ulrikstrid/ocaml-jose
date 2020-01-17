echo '{
    "version": "1.0.0",
    "name": "test",
    "dependencies": {
        "ocaml": "~'"$1"'",
        "@opam/dune": "1.11.0",
        "@opam/jose": "*"
    },
    "resolutions": {
        "@opam/nocrypto": "mirleft/ocaml-nocrypto:nocrypto.opam#80b7b4b9bd1ccfba3ec93d85cd82bfb3dc10f887",
        "@opam/jose": "link:./package.json"
    }
}' > "$1.json"

esy -P "$1"
