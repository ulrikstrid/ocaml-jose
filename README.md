# JOSE - JavaScript Object Signing and Encryption

JOSE implementation in ReasonML and OCaml

[![Build Status](https://dev.azure.com/strid/reason-jose/_apis/build/status/ulrikstrid.reason-jose?branchName=master)](https://dev.azure.com/strid/reason-jose/_build/latest?definitionId=39&branchName=master)

## Goals

This package aims to implement the JOSE specication.
The main usecase for JOSE is probably JWT singing and verification via JWKs.

## pre 1.0.0

Expect breaking changes on minor releases but patch should not be breaking.

I want to get feedback on both the API and implementation. Issues and PRs are more than welcome.

## Installation

Since we're using a currently unreleased version of nocrypto you have to pin that

With opam:

```
opam pin add nocrypto.dev git+https://github.com/mirleft/ocaml-nocrypto#dune
opam pin add jose.dev git+https://github.com/ulrikstrid/reason-jose
```

With esy:

```json
  "resolutions": {
    "@opam/nocrypto": "mirleft/ocaml-nocrypto:nocrypto.opam#80b7b4b9bd1ccfba3ec93d85cd82bfb3dc10f887"
  }
```
