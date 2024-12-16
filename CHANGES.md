next
--------------
- Upgrade mirage-crypto and remove cstruct

0.9.0
--------------
- Support all serialization formats, previously only the compact serialization was supported, now we support both general and flattened JSON format (by @ulrikstrid) 
- Add support for ES384 (P-384 with SHA384) (by @ulrikstrid) 
- Allow creating a JWK from X509 keys directly (by @ulrikstrid) 
- Support extra headers (by @ulrikstrid) 
- Add a parameter to JWT validation for the current time represented as `Ptime.t` (by @ulrikstrid)
- Add support for EdDSA keys (Ed25519 curve) from rfc8037 (by @ulrikstrid)

0.8.2
--------------
- JWS now properly checks the signature. Reported by @nankeen and fixed by @ulrikstrid. CVE-2023-23928


0.8.1
--------------
- Remove usage of Result.get_ok to maintain compatibility with older OCaml versions

0.8.0
--------------
- Make `use` and `alg` optional
- Correct thumbprint generation on all algs
- Add getters for claims
- Thumbprint is now a Cstruct.t instead of string which is less ambigious
- Make `header` argument optional when signing which simplifies the normal usecase

0.7.0
--------------
- Remove print statements that was used for debugging (by @phongphan)
- Make things safer by default, `of_string` will now return result, etc (by @anmonteiro)
- Fix deprecation warnings in libraries (by @anmonteiro)

0.6.0
--------------
- JWT/JWS/JWK: Add support for ES256 and ES512 signing via the updated mirage-crypto and x509 (by @ulrikstrid)
- JWT: [BREAKING] JWT will not validate `exp` by default anymore (by @ulrikstrid)

0.5.1
--------------
- JWA: Add Unsupported option and stop raising when encountering unknown `kty` (by @ulrikstrid)

0.5.0
--------------
- JWS: compare computed HMAC signatures in constant-time (by @anmonteiro)
- Adapt to Mirage-crypto 0.8.1, drops support for OCaml < 4.8.0 (breaking) (by @anmonteiro)

0.4.0
--------------
- RFC7638: Implement thumbprints (by @undu)
- Make kid optional in the header and jwk

0.3.1
--------------
- Add result compatability package (by @anmonteiro)
- Add `kid` to JWK representation to keep it when parsing JSON input
- Fix upper constraint on mirage-crypto

0.3.0
--------------
- Change the JWT representation to be based on a GADT, this allows us to use a private JWT for anything where a public JWT is enough.
- Add JWE encryption and decryption

0.2.0
--------------
- Change from nocrypto to mirage

0.1.0
--------------
- Initial release
