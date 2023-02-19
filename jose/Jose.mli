(** {1 JSON Web Algorithm}

    {{: https://www.tools.ietf.org/rfc/rfc7518.html } Link to RFC } *)
module Jwa : sig
  type alg =
    [ `RS256  (** HMAC using SHA-256 *)
    | `HS256  (** RSASSA-PKCS1-v1_5 using SHA-256 *)
    | `ES256  (** ECDSA using P-256 and SHA-256 *)
    | `ES384  (** ECDSA using P-384 and SHA-384 *)
    | `ES512  (** ECDSA using P-521 and SHA-512 *)
    | `EdDSA
    | `RSA_OAEP  (** RSAES OAEP using default parameters *)
    | `RSA1_5  (** RSA PKCS 1 *)
    | `None
    | `Unsupported of string ]

  (** {{: https://tools.ietf.org/html/rfc7518#section-3.1 } Link to RFC}

      - [RS256] and [HS256] and none is currently the only supported algs for
      signature - [RSA_OAEP] is currently the only supported alg for encryption *)

  val alg_to_string : alg -> string
  val alg_of_string : string -> alg
  val alg_to_json : alg -> Yojson.Safe.t
  val alg_of_json : Yojson.Safe.t -> alg

  type kty =
    [ `oct  (** Octet sequence (used to represent symmetric keys) *)
    | `RSA  (** RSA {{: https://tools.ietf.org/html/rfc3447} Link to RFC} *)
    | `EC  (** Elliptic Curve *)
    | `OKP
      (** Octet Key Pair {{: https://www.rfc-editor.org/rfc/rfc8037.html} Link to RFC} *)
    | `Unsupported of string ]
  (** {{: https://tools.ietf.org/html/rfc7518#section-6.1 } Link to RFC } *)

  val kty_to_string : kty -> string
  val kty_of_string : string -> kty

  type enc =
    [ `A128CBC_HS256
      (** AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm,
          https://tools.ietf.org/html/rfc7518#section-5.2.3 *)
    | `A256GCM  (** AES GCM using 256-bit key *) ]
  (** https://tools.ietf.org/html/rfc7518#section-5 *)

  val enc_to_string : enc -> string
  val enc_of_string : string -> enc
end

(** {1 JSON Web Key}

{{: https://tools.ietf.org/html/rfc7517 } Link to RFC } *)
module Jwk : sig
  type use = [ `Sig | `Enc | `Unsupported of string ]
  (** [use] will default to [`Sig] in all functions unless supplied *)

  type public = Public
  type priv = Private

  type 'key jwk = {
    alg : Jwa.alg option;  (** The algorithm for the key *)
    kty : Jwa.kty;  (** The key type for the key *)
    use : use option;
    kid : string option;  (** Key ID *)
    key : 'key;  (** The key implementation *)
  }

  type pub_rsa = Mirage_crypto_pk.Rsa.pub jwk
  (** [rsa] represents a public JWK with [kty] [`RSA] and a [Rsa.pub] key *)

  type priv_rsa = Mirage_crypto_pk.Rsa.priv jwk
  (** [rsa] represents a private JWK with [kty] [`RSA] and a [Rsa.priv] key *)

  type oct = string jwk
  (** [oct] represents a JWK with [kty] [`OCT] and a string key.

      [oct] will in most cases be a private key but there are some cases where
      it will be considered public, eg. if you parse a public JSON *)

  type priv_es256 = Mirage_crypto_ec.P256.Dsa.priv jwk
  (** [es256] represents a public JWK with [kty] [`EC] and a [P256.pub] key *)

  type pub_es256 = Mirage_crypto_ec.P256.Dsa.pub jwk
  (** [es256] represents a private JWK with [kty] [`EC] and a [P256.priv] key *)

  type priv_es384 = Mirage_crypto_ec.P384.Dsa.priv jwk
  (** [es384] represents a public JWK with [kty] [`EC] and a [P384.pub] key *)

  type pub_es384 = Mirage_crypto_ec.P384.Dsa.pub jwk
  (** [es384] represents a private JWK with [kty] [`EC] and a [P384.priv] key *)

  type priv_es512 = Mirage_crypto_ec.P521.Dsa.priv jwk
  (** [es512] represents a public JWK with [kty] [`EC] and a [P512.pub] key *)

  type pub_es512 = Mirage_crypto_ec.P521.Dsa.pub jwk
  (** [es512] represents a private JWK with [kty] [`EC] and a [P512.priv] key *)

  type priv_ed25519 = Mirage_crypto_ec.Ed25519.priv jwk
  (** [ed25519] represents a public JWK with [kty] [`OKP] and a [Ed25519.pub] key *)

  type pub_ed25519 = Mirage_crypto_ec.Ed25519.pub jwk
  (** [ed25519] represents a private JWK with [kty] [`OKP] and a [Ed25519.priv] key *)

  (** [t] describes a JSON Web Key which can be either [public] or [private] *)
  type 'a t =
    | Oct : oct -> 'a t
    | Rsa_priv : priv_rsa -> priv t
    | Rsa_pub : pub_rsa -> public t
    | Es256_priv : priv_es256 -> priv t
    | Es256_pub : pub_es256 -> public t
    | Es384_priv : priv_es384 -> priv t
    | Es384_pub : pub_es384 -> public t
    | Es512_priv : priv_es512 -> priv t
    | Es512_pub : pub_es512 -> public t
    | Ed25519_priv : priv_ed25519 -> priv t
    | Ed25519_pub : pub_ed25519 -> public t

  (** {1 Public keys}

      These keys are safe to show and should be used to verify signed content. *)

  val make_pub_rsa : ?use:use -> Mirage_crypto_pk.Rsa.pub -> public t
  (** [rsa_of_pub use pub] takes a public key generated by Nocrypto and returns
      a result t or a message of what went wrong. *)

  val of_pub_pem :
    ?use:use ->
    string ->
    (public t, [> `Msg of string | `Unsupported_kty ]) result
  (** [of_pub_pem use pem] takes a PEM as a string and returns a [public t] or a
      message of what went wrong. *)

  val to_pub_pem :
    'a t -> (string, [> `Msg of string | `Unsupported_kty ]) result
  (** [to_pub_pem t] takes a JWK and returns a result PEM string or a message of
      what went wrong. *)

  val of_pub_json :
    Yojson.Safe.t ->
    ( public t,
      [> `Json_parse_failed of string | `Msg of string | `Unsupported_kty ] )
    result
  (** [of_pub_json t] takes a [Yojson.Safe.t] and tries to return a [public t] *)

  val of_pub_json_string :
    string ->
    ( public t,
      [> `Json_parse_failed of string | `Msg of string | `Unsupported_kty ] )
    result
  (** [of_pub_json_string json_string] takes a JSON string representation and
      tries to return a [public t] *)

  val to_pub_json : 'a t -> Yojson.Safe.t
  (** [to_pub_json t] takes a [priv t] and returns a JSON representation *)

  val to_pub_json_string : 'a t -> string
  (** [to_pub_json_string t] takes a [priv t] and returns a JSON string
      representation *)

  (** {1 Private keys}

      These keys are not safe to show and should be used to sign content. *)

  val make_priv_rsa : ?use:use -> Mirage_crypto_pk.Rsa.priv -> priv t
  (** [make_priv_rsa use priv] takes a private key generated by Nocrypto and
      returns a priv t or a message of what went wrong. *)

  val of_priv_pem :
    ?use:use ->
    string ->
    (priv t, [> `Msg of string | `Unsupported_kty ]) result
  (** [of_priv_pem use pem] takes a PEM as a string and returns a [priv t] or a
      message of what went wrong. *)

  val make_oct : ?use:use -> string -> priv t
  (** [make_oct use secret] creates a [priv t] from a shared secret *)

  val to_priv_pem :
    priv t -> (string, [> `Msg of string | `Unsupported_kty ]) result
  (** [to_priv_pem t] takes a JWK and returns a result PEM string or a message
      of what went wrong. *)

  val of_priv_x509 :
    ?use:use ->
    X509.Private_key.t ->
    (priv t, [> `Msg of string | `Unsupported_kty ]) result

  val of_pub_x509 :
    ?use:use ->
    X509.Public_key.t ->
    (public t, [> `Msg of string | `Unsupported_kty ]) result

  val of_priv_json :
    Yojson.Safe.t ->
    ( priv t,
      [> `Json_parse_failed of string | `Msg of string | `Unsupported_kty ] )
    result
  (** [of_json json] takes a [Yojson.Safe.t] and returns a [priv t] *)

  val of_priv_json_string :
    string ->
    ( priv t,
      [> `Json_parse_failed of string | `Msg of string | `Unsupported_kty ] )
    result
  (** [of_priv_json_string json_string] takes a JSON string representation and
      tries to return a [private t] *)

  val to_priv_json : priv t -> Yojson.Safe.t
  (** [to_json t] takes a [t] and returns a [Yojson.Safe.t] *)

  val to_priv_json_string : priv t -> string
  (** [to_priv_json_string t] takes a [priv t] and returns a JSON string
      representation *)

  val pub_of_priv : priv t -> public t
  (** [pub_of_priv t] takes a [priv t] and returns the coresponding public key.

      When using it on [Oct] keys it will just return the same as it's a
      symetric key. *)

  (** {1 Utils }
  
  Utils to get different data from a JWK *)

  val get_kid : 'a t -> string option
  (** [get_kid jwk] is a convencience function to get the kid string *)

  val get_kty : 'a t -> Jwa.kty
  (** [get_kty jwk] is a convencience function to get the key type *)

  val get_alg : 'a t -> Jwa.alg option
  (** [get_alg jwk] is a convencience function to get the algorithm *)

  val get_thumbprint :
    Mirage_crypto.Hash.hash -> 'a t -> (Cstruct.t, [> `Unsafe ]) result
  (** [get_thumbprint hash jwk] calculates the thumbprint of [jwk] with [hash],
      following {{: https://tools.ietf.org/html/rfc7638 } RFC 7638 }.

      Returns an error for symmetric keys: sharing the hash may leak information
      about the key itself ans it's deemed unsafe. *)

  val use_to_string : use -> string
  val use_of_string : string -> use
end

(** {1 JSON Web Key Set}

    {{: https://tools.ietf.org/html/rfc7517#section-5 } Link to RFC } *)
module Jwks : sig
  type t = { keys : Jwk.public Jwk.t list }
  (** [t] describes a Private JSON Web Key Set *)

  val to_json : t -> Yojson.Safe.t
  (** [to_json t] takes a [t] and returns a [Yojson.Safe.t] *)

  val of_json : Yojson.Safe.t -> t
  (** [of_json json] takes a [Yojson.Safe.t] and returns a [t]. Keys that can
      not be serialized safely will be removed from the list *)

  val of_string : string -> t
  (** [of_string json_string] takes a JSON string representation and returns a
      [t]. Keys that can not be serialized safely will be removed from the list *)

  val to_string : t -> string
  (** [to_string t] takes a t and returns a JSON string representation *)

  val find_key : t -> string -> Jwk.public Jwk.t option
end

module Header : sig
  type t = {
    alg : Jwa.alg;
    jwk : Jwk.public Jwk.t option;
    kid : string option;
    x5t : string option;
    x5t256 : string option;
    typ : string option;
    cty : string option;
    enc : Jwa.enc option;
    extra : (string * Yojson.Safe.t) list;
  }
  (** The [header] has the following properties:
  
  - [alg] {! Jwa.alg }
  - [jwk] JSON Web Key
  - [kid] Key ID - We currently always expect this to be there, this can change in the future
  - [x5t] X.509 Certificate SHA-1 Thumbprint -
  - [x5t#S256] X.509 Certificate SHA-256 Thumbprint
  - [typ] Type
  - [cty] Content Type Not implemented
  
      {{: https://tools.ietf.org/html/rfc7515#section-4.1 } Link to RFC }

      {{: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-header-parameters } Complete list of registered header parameters} *)

  val make_header :
    ?typ:string ->
    ?alg:Jwa.alg ->
    ?enc:Jwa.enc ->
    ?extra:(string * Yojson.Safe.t) list ->
    ?jwk_header:bool ->
    Jwk.priv Jwk.t ->
    t
  (** [make_header typ alg enc jwk] if [alg] is not provided it will be derived
      from [jwk]. [jwk_header] decides if the jwk should be put in the header. *)

  val of_string : string -> (t, [> `Msg of string ]) result
  val to_string : t -> string
  val to_json : t -> Yojson.Safe.t
  val of_json : Yojson.Safe.t -> (t, [> `Msg of string ]) result
end

(** {1 JSON Web Signature}

    {{: https://tools.ietf.org/html/rfc7515 } Link to RFC } *)
module Jws : sig
  type signature = string

  type t = {
    header : Header.t;
    raw_header : string;
    payload : string;
    signature : signature;
  }

  type serialization = [ `Compact | `General | `Flattened ]

  val of_string :
    string -> (t, [> `Msg of string | `Not_json | `Not_supported ]) result

  val to_string : ?serialization:serialization -> t -> string

  val validate :
    jwk:'a Jwk.t -> t -> (t, [> `Invalid_signature | `Msg of string ]) result
  (** [validate jwk t] validates the signature *)

  val sign :
    ?header:Header.t ->
    payload:string ->
    Jwk.priv Jwk.t ->
    (t, [> `Msg of string ]) result
  (** [sign header payload priv] creates a signed JWT from [header] and
      [payload]

      We will start using a private JWK instead of a Mirage_crypto_pk.Rsa.priv
      soon *)
end

(** {1 JSON Web Token} *)
module Jwt : sig
  type payload = Yojson.Safe.t
  type claim = string * Yojson.Safe.t

  val empty_payload : payload

  type t = {
    header : Header.t;
    raw_header : string;
    payload : payload;
    raw_payload : string;
    signature : Jws.signature;
  }

  val add_claim : string -> Yojson.Safe.t -> payload -> payload
  val get_yojson_claim : t -> string -> Yojson.Safe.t option
  val get_string_claim : t -> string -> string option
  val get_int_claim : t -> string -> int option
  val to_string : ?serialization:Jws.serialization -> t -> string

  val of_string :
    jwk:'a Jwk.t ->
    now:Ptime.t ->
    string ->
    ( t,
      [> `Expired
      | `Invalid_signature
      | `Msg of string
      | `Not_json
      | `Not_supported ] )
    result
  (** [of_string ~jwk jwt_string] parses and validates the encoded JWT string. *)

  val unsafe_of_string :
    string -> (t, [> `Msg of string | `Not_json | `Not_supported ]) result

  val to_jws : t -> Jws.t
  val of_jws : Jws.t -> t

  val validate_signature :
    jwk:'a Jwk.t -> t -> (t, [> `Invalid_signature | `Msg of string ]) result
  (** [validate_signature ~jwk t] checks if the JWT is valid and then calls
      Jws.validate to validate the signature *)

  val check_expiration : now:Ptime.t -> t -> (t, [> `Expired ]) result
  (** [check_expiration ~now t] checks whether the JWT is valid at the current time. *)

  val validate :
    jwk:'a Jwk.t ->
    now:Ptime.t ->
    t ->
    (t, [> `Expired | `Invalid_signature | `Msg of string ]) result
  (** [validate ~jwk ~now t] does the same validation as `validate_signature` and
      additionally checks expiration. *)

  val sign :
    ?header:Header.t ->
    payload:payload ->
    Jwk.priv Jwk.t ->
    (t, [> `Msg of string ]) result
  (** [sign header payload priv] creates a signed JWT from [header] and
      [payload]

      We will start using a private JWK instead of a Mirage_crypto_pk.Rsa.priv
      soon *)
end

module Jwe : sig
  (** {{: https://tools.ietf.org/html/rfc7516 } Link to RFC } *)

  type t = {
    header : Header.t;
    cek : string;  (** Content Encryption Key *)
    iv : string;  (** Initialization Vector*)
    payload : string;  (** plaintext to be encrypted *)
    aad : string option;  (** Additional Authentication Data, for future use *)
  }
  (** A JWE ready for encryption *)

  val make :
    header:Header.t ->
    string ->
    (t, [> `Missing_enc | `Unsupported_alg ]) result
  (** [make header payload] creates a JWE from a {! Header.t } and the plaintext
      that you want to encrypt *)

  val encrypt :
    jwk:'a Jwk.t ->
    t ->
    ( string,
      [> `Invalid_alg | `Missing_enc | `Unsupported_enc | `Unsupported_kty ] )
    result
  (** [encrypt jwk t] encrypts a {! t } into the compact string format *)

  val decrypt :
    jwk:Jwk.priv Jwk.t ->
    string ->
    ( t,
      [> `Invalid_JWE | `Invalid_JWK | `Decrypt_cek_failed | `Msg of string ]
    )
    result
  (** [decrypt jwk string] decrypts a compact string formated JWE into a {! t } *)
end
