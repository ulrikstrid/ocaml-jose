type kty =
  [ `oct
    (** Octet sequence (used to represent symmetric keys) - Required
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-6.1} RFC 7518 §6.1})
    *)
  | `RSA
    (** RSA - Required
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-6.1} RFC 7518 §6.1})
    *)
  | `EC
    (** Elliptic Curve - Recommended+
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-6.1} RFC 7518 §6.1})
    *)
  | `OKP
    (** Octet Key Pair - Optional
        ({{:https://www.rfc-editor.org/info/rfc8037/#section-2} RFC 8037 §2}) *)
  | `Unsupported of string ]

let kty_to_string : kty -> string = function
  | `oct -> "oct"
  | `RSA -> "RSA"
  | `EC -> "EC"
  | `OKP -> "OKP"
  | `Unsupported str -> str

let kty_of_string : string -> kty = function
  | "oct" -> `oct
  | "RSA" -> `RSA
  | "EC" -> `EC
  | "OKP" -> `OKP
  | str -> `Unsupported str

type alg =
  [ `RS256
    (** RSASSA-PKCS1-v1_5 using SHA-256 - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1})
    *)
  | `HS256
    (** HMAC using SHA-256 - Required
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1})
    *)
  | `ES256
    (** ECDSA using P-256 and SHA-256 - Recommended+
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1})
    *)
  | `ES384
    (** ECDSA using P-384 and SHA-384 - Optional
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1})
    *)
  | `ES512
    (** ECDSA using P-521 and SHA-512 - Optional
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1})
    *)
  | `EdDSA
    (** EdDSA signature algorithm - Optional
        ({{:https://www.rfc-editor.org/info/rfc8037/#section-3.1} RFC 8037 §3.1})
    *)
  | `Ed25519
    (** Ed25519 signature algorithm - Fully-specified replacement for EdDSA
        ({{:https://www.rfc-editor.org/info/rfc9864/#section-3.1} RFC 9864 §3.1})
    *)
  | `RSA_OAEP
    (** RSAES OAEP using default parameters - Recommended+
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1})
    *)
  | `RSA1_5
    (** RSA PKCS 1 v1.5 - Recommended-
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1})
    *)
  | `Dir
    (** Direct use of a shared symmetric key - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1})
    *)
  | `A128KW
    (** AES Key Wrap using 128-bit key - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1},
        {{:https://www.rfc-editor.org/info/rfc3394} RFC 3394}) *)
  | `A256KW
    (** AES Key Wrap using 256-bit key - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1},
        {{:https://www.rfc-editor.org/info/rfc3394} RFC 3394}) *)
  | `ECDH_ES
    (** Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using
        Concat KDF - Recommended+
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1},
        {{:https://www.rfc-editor.org/info/rfc7518/#section-4.6} §4.6}) *)
  | `ECDH_ES_A128KW
    (** ECDH-ES using Concat KDF and CEK wrapped with "A128KW" - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1},
        {{:https://www.rfc-editor.org/info/rfc7518/#section-4.6} §4.6}) *)
  | `ECDH_ES_A256KW
    (** ECDH-ES using Concat KDF and CEK wrapped with "A256KW" - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.6} RFC 7518 §4.6},
        {{:https://www.rfc-editor.org/info/rfc7518/#section-4.6} §4.6}) *)
  | `None
    (** No digital signature or MAC performed - Optional
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1})
    *)
  | `Unsupported of string ]

let alg_to_string = function
  | `RS256 -> "RS256"
  | `HS256 -> "HS256"
  | `ES256 -> "ES256"
  | `ES384 -> "ES384"
  | `ES512 -> "ES512"
  | `EdDSA -> "EdDSA"
  | `Ed25519 -> "Ed25519"
  | `RSA_OAEP -> "RSA-OAEP"
  | `RSA1_5 -> "RSA1_5"
  | `Dir -> "dir"
  | `A128KW -> "A128KW"
  | `A256KW -> "A256KW"
  | `ECDH_ES -> "ECDH-ES"
  | `ECDH_ES_A128KW -> "ECDH-ES+A128KW"
  | `ECDH_ES_A256KW -> "ECDH-ES+A256KW"
  | `None -> "none"
  | `Unsupported string -> string

let alg_of_string = function
  | "RS256" -> `RS256
  | "HS256" -> `HS256
  | "ES256" -> `ES256
  | "ES384" -> `ES384
  | "ES512" -> `ES512
  | "EdDSA" -> `EdDSA
  | "Ed25519" -> `Ed25519
  | "RSA-OAEP" -> `RSA_OAEP
  | "RSA1_5" -> `RSA1_5
  | "dir" -> `Dir
  | "A128KW" -> `A128KW
  | "A256KW" -> `A256KW
  | "ECDH-ES" -> `ECDH_ES
  | "ECDH-ES+A128KW" -> `ECDH_ES_A128KW
  | "ECDH-ES+A256KW" -> `ECDH_ES_A256KW
  | "none" -> `None
  | str -> `Unsupported str

let alg_to_json alg = `String (alg_to_string alg)
let alg_of_json json = Yojson.Safe.Util.to_string json |> alg_of_string

type enc =
  [ `A128CBC_HS256
    (** AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm - Required
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-5.1} RFC 7518 §5.1},
        {{:https://www.rfc-editor.org/info/rfc7518/#section-5.2.3} §5.2.3})
        https://tools.ietf.org/html/rfc7518#section-5.2.3 *)
  | `A256CBC_HS512
    (** AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm - Required
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-5.1} RFC 7518 §5.1},
        {{:https://www.rfc-editor.org/info/rfc7518/#section-5.2.5} §5.2.5})
        https://tools.ietf.org/html/rfc7518#section-5.2.5 *)
  | `A128GCM
    (** AES GCM using 128-bit key - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-5.1} RFC 7518 §5.1},
        {{:https://www.rfc-editor.org/info/rfc7518/#section-5.3} §5.3}) *)
  | `A256GCM
    (** AES GCM using 256-bit key - Recommended
        ({{:https://www.rfc-editor.org/info/rfc7518/#section-5.1} RFC 7518 §5.1},
        {{:https://www.rfc-editor.org/info/rfc7518/#section-5.3} §5.3}) *) ]
(** Content Encryption Algorithms for JWE
    ({{:https://www.rfc-editor.org/info/rfc7518/#section-5.1} RFC 7518 §5.1}) *)

let enc_to_string enc =
  match enc with
  | `A128CBC_HS256 -> "A128CBC-HS256"
  | `A256CBC_HS512 -> "A256CBC-HS512"
  | `A128GCM -> "A128GCM"
  | `A256GCM -> "A256GCM"

let enc_of_string enc =
  match enc with
  | "A128CBC-HS256" -> `A128CBC_HS256
  | "A256CBC-HS512" -> `A256CBC_HS512
  | "A128GCM" -> `A128GCM
  | "A256GCM" -> `A256GCM
  | _ -> raise Not_found

let enc_to_length = function
  | `A128CBC_HS256 -> 256
  | `A256CBC_HS512 -> 512
  | `A128GCM -> 128
  | `A256GCM -> 256

let enc_to_iv_length = function
  | `A128CBC_HS256 -> Mirage_crypto.AES.CBC.block_size
  | `A256CBC_HS512 -> Mirage_crypto.AES.CBC.block_size
  (* https://www.rfc-editor.org/info/rfc7518/#section-5.3 12*8 = 96 bits*)
  | `A128GCM -> 12
  | `A256GCM -> 12
