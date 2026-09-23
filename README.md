# JOSE - JavaScript Object Signing and Encryption

JOSE implementation in OCaml.

## Goals

This package aims to implement the JOSE specification.
The main usecase for JOSE is probably JWT signing and verification via JWKs.

## Installation

Install `jose` using opam:

```bash
opam install jose
```

## Examples

Make sure to initialize the random number generator (required by `mirage-crypto`) before performing cryptographic operations:

```ocaml
let () = Mirage_crypto_rng_unix.use_default ()
```

### JWS (JSON Web Signature)

Sign and verify arbitrary payload with a key (symmetric `oct` or asymmetric `RSA`, `EC`, `OKP`):

```ocaml
(* 1. Create or load a key *)
let jwk = Jose.Jwk.make_oct "a-secret-key-that-is-at-least-32-bytes"

(* 2. Sign a payload *)
let jws = Jose.Jws.sign ~payload:"Hello, JWS!" jwk |> Result.get_ok

(* 3. Serialize to compact representation ("<header>.<payload>.<signature>") *)
let token = Jose.Jws.to_string jws

(* 4. Parse and validate signature *)
let parsed_jws = Jose.Jws.of_string token |> Result.get_ok
let validated_jws = Jose.Jws.validate ~jwk parsed_jws |> Result.get_ok
let payload = validated_jws.payload (* "Hello, JWS!" *)
```

### JWE (JSON Web Encryption)

Encrypt and decrypt plaintext payloads:

```ocaml
(* 1. Create or load an encryption key *)
let jwk = Jose.Jwk.make_oct ~use:`Enc "a-secret-key-that-is-at-least-32-bytes"

(* 2. Create a JWE header with key management and content encryption algorithms *)
let header = Jose.Header.make_header ~alg:`Dir ~enc:`A256GCM jwk

(* 3. Encrypt the plaintext into compact representation *)
let jwe = Jose.Jwe.make ~header "Secret payload data" |> Result.get_ok
let encrypted_token = Jose.Jwe.encrypt ~jwk jwe |> Result.get_ok

(* 4. Decrypt using the key *)
let decrypted_jwe = Jose.Jwe.decrypt ~jwk encrypted_token |> Result.get_ok
let payload = decrypted_jwe.payload (* "Secret payload data" *)
```

### JWT (JSON Web Token)

Create, sign, and validate tokens with claim and expiration verification:

```ocaml
(* 1. Create or load a key *)
let jwk = Jose.Jwk.make_oct "a-secret-key-that-is-at-least-32-bytes"

(* 2. Build payload with claims *)
let now = Ptime.of_float_s (Unix.time ()) |> Option.get
let exp =
  Ptime.add_span now (Ptime.Span.v (0, 3600L * 1_000_000_000_000L))
  |> Option.get

let payload =
  Jose.Jwt.empty_payload
  |> Jose.Jwt.add_claim "sub" (`String "user_123")
  |> Jose.Jwt.add_claim "exp" (`Int (Ptime.to_span exp |> Ptime.Span.to_int_s |> Option.get))

(* 3. Sign the token *)
let jwt = Jose.Jwt.sign ~payload jwk |> Result.get_ok
let token_string = Jose.Jwt.to_string jwt

(* 4. Parse and validate signature and expiration *)
let validated_jwt = Jose.Jwt.of_string ~jwk ~now token_string |> Result.get_ok
let user_id = Jose.Jwt.get_string_claim validated_jwt "sub" (* Some "user_123" *)
```

## Algorithm Compatibility

The compatibility tables below are automatically extracted from the codebase using `scripts/extract_compatibility.py`.

<!-- COMPATIBILITY_TABLE_START -->

### JWS Digital Signature and MAC Algorithms (`alg`)

| Algorithm | Description | Requirement | RFC Reference | Supported |
| :--- | :--- | :--- | :--- | :---: |
| `HS256` | HMAC using SHA-256 | Required | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | Yes |
| `HS384` | HMAC using SHA-384 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | No |
| `HS512` | HMAC using SHA-512 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | No |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 | Recommended | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | Yes |
| `RS384` | RSASSA-PKCS1-v1_5 using SHA-384 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | No |
| `RS512` | RSASSA-PKCS1-v1_5 using SHA-512 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | No |
| `ES256` | ECDSA using P-256 and SHA-256 | Recommended+ | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | Yes |
| `ES384` | ECDSA using P-384 and SHA-384 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | Yes |
| `ES512` | ECDSA using P-521 and SHA-512 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | Yes |
| `PS256` | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | No |
| `PS384` | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | No |
| `PS512` | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | No |
| `EdDSA` | EdDSA signature algorithm (deprecated by RFC 9864) | Optional | [RFC 8037 §3.1](https://www.rfc-editor.org/info/rfc8037/#section-3.1) | Yes |
| `Ed25519` | Ed25519 signature algorithm | Optional | [RFC 9864 §3.1](https://www.rfc-editor.org/info/rfc9864/#section-3.1) | Yes |
| `Ed448` | Ed448 signature algorithm | Optional | [RFC 9864 §3.1](https://www.rfc-editor.org/info/rfc9864/#section-3.1) | No |
| `none` | No digital signature or MAC performed | Optional | [RFC 7518 §3.1](https://www.rfc-editor.org/info/rfc7518/#section-3.1) | Yes |

### JWE Key Management Algorithms (`alg`)

| Algorithm | Key Management Algorithm | Requirement | RFC Reference | Supported |
| :--- | :--- | :--- | :--- | :---: |
| `RSA1_5` | RSAES-PKCS1-v1_5 | Recommended- | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | Yes |
| `RSA-OAEP` | RSAES OAEP using default parameters | Recommended+ | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | Yes |
| `RSA-OAEP-256` | RSAES OAEP using SHA-256 and MGF1 with SHA-256 | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | No |
| `A128KW` | AES Key Wrap using 128-bit key | Recommended | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [RFC 3394](https://www.rfc-editor.org/info/rfc3394) | Yes |
| `A192KW` | AES Key Wrap using 192-bit key | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [RFC 3394](https://www.rfc-editor.org/info/rfc3394) | No |
| `A256KW` | AES Key Wrap using 256-bit key | Recommended | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [RFC 3394](https://www.rfc-editor.org/info/rfc3394) | Yes |
| `dir` | Direct use of a shared symmetric key | Recommended | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | Yes |
| `ECDH-ES` | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF | Recommended+ | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [§4.6](https://www.rfc-editor.org/info/rfc7518/#section-4.6) | Yes |
| `ECDH-ES+A128KW` | ECDH-ES using Concat KDF and CEK wrapped with "A128KW" | Recommended | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [§4.6](https://www.rfc-editor.org/info/rfc7518/#section-4.6) | Yes |
| `ECDH-ES+A192KW` | ECDH-ES using Concat KDF and CEK wrapped with "A192KW" | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [§4.6](https://www.rfc-editor.org/info/rfc7518/#section-4.6) | No |
| `ECDH-ES+A256KW` | ECDH-ES using Concat KDF and CEK wrapped with "A256KW" | Recommended | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [§4.6](https://www.rfc-editor.org/info/rfc7518/#section-4.6) | Yes |
| `A128GCMKW` | Key wrapping with AES GCM using 128-bit key | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | No |
| `A192GCMKW` | Key wrapping with AES GCM using 192-bit key | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | No |
| `A256GCMKW` | Key wrapping with AES GCM using 256-bit key | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | No |
| `PBES2-HS256+A128KW` | PBES2 with HMAC SHA-256 and "A128KW" wrapping | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | No |
| `PBES2-HS384+A192KW` | PBES2 with HMAC SHA-384 and "A192KW" wrapping | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | No |
| `PBES2-HS512+A256KW` | PBES2 with HMAC SHA-512 and "A256KW" wrapping | Optional | [RFC 7518 §4.1](https://www.rfc-editor.org/info/rfc7518/#section-4.1) | No |

### JWE Content Encryption Algorithms (`enc`)

| Algorithm | Content Encryption Algorithm | Requirement | RFC Reference | Supported |
| :--- | :--- | :--- | :--- | :---: |
| `A128CBC-HS256` | AES_128_CBC_HMAC_SHA_256 authenticated encryption | Required | [RFC 7518 §5.1](https://www.rfc-editor.org/info/rfc7518/#section-5.1), [§5.2.3](https://www.rfc-editor.org/info/rfc7518/#section-5.2.3) | Yes |
| `A192CBC-HS384` | AES_192_CBC_HMAC_SHA_384 authenticated encryption | Optional | [RFC 7518 §5.1](https://www.rfc-editor.org/info/rfc7518/#section-5.1), [§5.2.4](https://www.rfc-editor.org/info/rfc7518/#section-5.2.4) | No |
| `A256CBC-HS512` | AES_256_CBC_HMAC_SHA_512 authenticated encryption | Required | [RFC 7518 §5.1](https://www.rfc-editor.org/info/rfc7518/#section-5.1), [§5.2.5](https://www.rfc-editor.org/info/rfc7518/#section-5.2.5) | Yes |
| `A128GCM` | AES GCM using 128-bit key | Recommended | [RFC 7518 §5.1](https://www.rfc-editor.org/info/rfc7518/#section-5.1), [§5.3](https://www.rfc-editor.org/info/rfc7518/#section-5.3) | Yes |
| `A192GCM` | AES GCM using 192-bit key | Optional | [RFC 7518 §5.1](https://www.rfc-editor.org/info/rfc7518/#section-5.1), [§5.3](https://www.rfc-editor.org/info/rfc7518/#section-5.3) | No |
| `A256GCM` | AES GCM using 256-bit key | Recommended | [RFC 7518 §5.1](https://www.rfc-editor.org/info/rfc7518/#section-5.1), [§5.3](https://www.rfc-editor.org/info/rfc7518/#section-5.3) | Yes |

### JSON Web Key Types (`kty`)

| Key Type (`kty`) | Description | Requirement | RFC Reference | Supported |
| :--- | :--- | :--- | :--- | :---: |
| `EC` | Elliptic Curve | Recommended+ | [RFC 7518 §6.1](https://www.rfc-editor.org/info/rfc7518/#section-6.1) | Yes |
| `RSA` | RSA | Required | [RFC 7518 §6.1](https://www.rfc-editor.org/info/rfc7518/#section-6.1) | Yes |
| `oct` | Octet sequence (used to represent symmetric keys) | Required | [RFC 7518 §6.1](https://www.rfc-editor.org/info/rfc7518/#section-6.1) | Yes |
| `OKP` | Octet Key Pair | Optional | [RFC 8037 §2](https://www.rfc-editor.org/info/rfc8037/#section-2) | Yes |

<!-- COMPATIBILITY_TABLE_END -->

To update or check the compatibility tables:

```bash
# Update README.md in-place
python3 scripts/extract_compatibility.py --update-readme

# Check if README.md is in sync (e.g. in CI)
python3 scripts/extract_compatibility.py --check
```

## pre 1.0.0

Expect breaking changes on minor releases but patch should not be breaking.

I want to get feedback on both the API and implementation. Issues and PRs are more than welcome.
