type kty =
  [ `oct  (** Octet sequence (used to represent symmetric keys) *)
  | `RSA  (** RSA *)
  | `EC  (** Elliptic Curve *)
  | `OKP  (** Octet Key Pair *)
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
  [ `RS256  (** HMAC using SHA-256 *)
  | `HS256  (** RSASSA-PKCS1-v1_5 using SHA-256 *)
  | `ES256  (** ECDSA using P-256 and SHA-256 *)
  | `ES384  (** ECDSA using P-384 and SHA-384 *)
  | `ES512  (** ECDSA using P-521 and SHA-512 *)
  | `EdDSA  (**  *)
  | `RSA_OAEP  (** RSAES OAEP using default parameters *)
  | `RSA1_5  (** RSA PKCS 1 *)
  | `None
  | `Unsupported of string ]

let alg_to_string = function
  | `RS256 -> "RS256"
  | `HS256 -> "HS256"
  | `ES256 -> "ES256"
  | `ES384 -> "ES384"
  | `ES512 -> "ES512"
  | `EdDSA -> "EdDSA"
  | `RSA_OAEP -> "RSA-OAEP"
  | `RSA1_5 -> "RSA1_5"
  | `None -> "none"
  | `Unsupported string -> string

let alg_of_string = function
  | "RS256" -> `RS256
  | "HS256" -> `HS256
  | "ES256" -> `ES256
  | "ES384" -> `ES384
  | "ES512" -> `ES512
  | "EdDSA" -> `EdDSA
  | "RSA-OAEP" -> `RSA_OAEP
  | "RSA1_5" -> `RSA1_5
  | "none" -> `None
  | str -> `Unsupported str

let alg_to_json alg = `String (alg_to_string alg)
let alg_of_json json = Yojson.Safe.Util.to_string json |> alg_of_string

type enc =
  [ `A128CBC_HS256
    (** AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm,
        https://tools.ietf.org/html/rfc7518#section-5.2.3 *)
  | `A256GCM  (** AES GCM using 256-bit key *) ]
(** https://tools.ietf.org/html/rfc7518#section-5 *)

let enc_to_string enc =
  match enc with `A128CBC_HS256 -> "A128CBC-HS256" | `A256GCM -> "A256GCM"

let enc_of_string enc =
  match enc with
  | "A128CBC-HS256" -> `A128CBC_HS256
  | "A256GCM" -> `A256GCM
  | _ -> raise Not_found

let enc_to_length = function `A128CBC_HS256 -> 256 | `A256GCM -> 256
