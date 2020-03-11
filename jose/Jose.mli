(**
{1 JSON Web Key}

{{: https://tools.ietf.org/html/rfc7517 } Link to RFC }
*)
module Jwk : sig
  (**
  {1 Public keys}
  These keys are safe to show and should be used to verify signed content.
  *)
  module Pub : sig
    type oct = {
      kty : Jwa.kty;
      (* `oct *)
      alg : Jwa.alg;
      (* `HS256 *)
      kid : string;
      k : string;
    }
    (** [oct] represents a JWK with [kty] [`oct] *)

    type rsa = {
      alg : Jwa.alg;
      kty : Jwa.kty;
      use : string option;
      n : string;
      e : string;
      kid : string;
      x5t : string option;
    }
    (** [rsa] represents a JWK with [kty] [`RSA] *)

    (**
    [t] describes a Public JSON Web Key
    *)
    type t = RSA of rsa | OCT of oct

    val get_kid : t -> string
    (** [get_kid jwk] is a convencience function to get the kid string *)

    val get_kty : t -> Jwa.kty
    (** [get_kty jwk] is a convencience function to get the key type *)

    val get_alg : t -> Jwa.alg
    (** [get_alg jwk] is a convencience function to get the algorithm *)

    val rsa_of_pub : Mirage_crypto_pk.Rsa.pub -> (rsa, [> `Msg of string ]) result
    (**
    [rsa_of_pub pub] takes a public key generated by Nocrypto and returns a result t or a message of what went wrong.
    *)

    val rsa_to_pub : rsa -> (Mirage_crypto_pk.Rsa.pub, [> `Msg of string ]) result
    (**
    [rsa_to_pub t] takes a public JWK and returns a result [Mirage_crypto_pk.Rsa.pub] or a message of what went wrong.
    *)

    val rsa_of_pub_pem : string -> (rsa, [> `Msg of string ]) result
    (**
    [rsa_of_pub_pem pem] takes a public PEM as a string and returns a result a result t or a message of what went wrong.
    *)

    val rsa_to_pub_pem : rsa -> (string, [> `Msg of string ]) result
    (**
    [rsa_to_pub_pem t] takes a public JWK and returns a result public PEM string or a message of what went wrong.
    *)

    val oct_of_string : string -> oct
    (**
    [oct_of_string secret] creates a [oct] from a shared secret
    *)

    val to_json : t -> Yojson.Safe.t
    (**
    [to_json t] takes a [t] and returns a [Yojson.Safe.t]
    *)

    val of_json : Yojson.Safe.t -> (t, [> `Msg of string ]) result
    (**
    [of_json json] takes a [Yojson.Safe.t] and returns a [t]
    *)

    val of_string : string -> (t, [> `Msg of string ]) result
    (**
    [of_string json_string] takes a JSON string representation and tries to return a [t]
    *)

    val to_string : t -> string
    (**
    [to_string t] takes a t and returns a JSON string representation
    *)
  end

  (**
  {1 Private keys}

  These keys are not safe to show and should be used to sign content.
  *)
  module Priv : sig
    type oct = {
      kty : Jwa.kty;
      (* `oct *)
      alg : Jwa.alg;
      (* `HS256 *)
      kid : string;
      k : string;
    }

    type rsa = {
      alg : Jwa.alg;
      kty : Jwa.kty;
      n : string;
      e : string;
      d : string;
      p : string;
      q : string;
      dp : string;
      dq : string;
      qi : string;
      kid : string;
    }
    (**
    [rsa] describes a Private RSA JSON Web Key
    *)

    type t = RSA of rsa | OCT of oct

    val get_kid : t -> string
    (** [get_kid jwk] is a convencience function to get the kid string *)

    val get_kty : t -> Jwa.kty
    (** [get_kty jwk] is a convencience function to get the key type *)

    val get_alg : t -> Jwa.alg
    (**
    [get_alg jwk] is a convencience function to get the algorithm
    *)

    val rsa_of_priv : Mirage_crypto_pk.Rsa.priv -> (rsa, [> `Msg of string ]) result
    (**
    [of_priv priv] takes a private key generated by Nocrypto and returns a result t or a message of what went wrong.
    *)

    val rsa_to_priv : rsa -> (Mirage_crypto_pk.Rsa.priv, [> `Msg of string ]) result
    (**
    [to_priv t] takes a private JWK and returns a result Mirage_crypto_pk.Rsa.priv or a message of what went wrong.
    *)

    val rsa_of_priv_pem : string -> (rsa, [> `Msg of string ]) result
    (**
    [of_priv_pem pem] takes a PEM as a string and returns a result a result t or a message of what went wrong.
    *)

    val rsa_to_priv_pem : rsa -> (string, [> `Msg of string ]) result
    (**
    [to_priv_pem t] takes a private JWK and returns a result PEM string or a message of what went wrong.
    *)

    val oct_of_string : string -> oct
    (**
    [oct_of_string secret] creates a [oct] from a shared secret
    *)

    val to_json : t -> Yojson.Safe.t
    (**
    [to_json t] takes a [t] and returns a [Yojson.Safe.t]
    *)

    val of_json : Yojson.Safe.t -> (t, [> `Msg of string ]) result
    (**
    [of_json json] takes a [Yojson.Safe.t] and returns a [t]
    *)

    val of_string : string -> (t, [> `Msg of string ]) result
    (**
    [of_string json_string] takes a JSON string representation and tries to return a [t]
    *)

    val to_string : t -> string
    (**
    [to_string t] takes a t and returns a JSON string representation
    *)
  end
end

(**
{1 JSON Web Key Set}

{{: https://tools.ietf.org/html/rfc7517#section-5 } Link to RFC }
*)
module Jwks : sig
  type t = { keys : Jwk.Pub.t list }
  (**  [t] describes a Private JSON Web Key Set *)

  val to_json : t -> Yojson.Safe.t
  (**
  [to_json t] takes a [t] and returns a [Yojson.Safe.t]
  *)

  val of_json : Yojson.Safe.t -> t
  (**
  [of_json json] takes a [Yojson.Safe.t] and returns a [t].
  Keys that can not be serialized safely will be removed from the list
  *)

  val of_string : string -> t
  (**
    [of_string json_string] takes a JSON string representation and returns a [t].
    Keys that can not be serialized safely will be removed from the list
    *)

  val to_string : t -> string
  (**
  [to_string t] takes a t and returns a JSON string representation
  *)

  val find_key : t -> string -> Jwk.Pub.t option
end

(**
{1 JSON Web Algorithm}

{{: https://www.tools.ietf.org/rfc/rfc7518.html } Link to RFC }
*)
module Jwa : sig
  type alg = [ `RS256 | `HS256 | `none | `Unknown ]
  (**
  RS256 and HS256 and none is currently the only supported algs
  *)

  val alg_to_string : alg -> string

  val alg_of_string : string -> alg

  val alg_to_json : alg -> Yojson.Safe.t

  val alg_of_json : Yojson.Safe.t -> alg

  type kty = [ `oct | `RSA | `EC ]

  val kty_to_string : kty -> string

  val kty_of_string : string -> kty
end

module Header : sig
  type t = {
    alg : Jwa.alg;
    jku : string option;
    jwk : Jwk.Pub.t option;
    kid : string option;
    x5t : string option;
    x5t256 : string option;
    typ : string option;
    cty : string option;
  }
  (**
    The [header] has the following properties:
    - [alg] Jwa - RS256 and none is currently the only supported algs
    - [jku] JWK Set URL
    - [jwk] JSON Web Key
    - [kid] Key ID - We currently always expect this to be there, this can change in the future
    - [x5t] X.509 Certificate SHA-1 Thumbprint
    - [x5t#S256] X.509 Certificate SHA-256 Thumbprint
    - [typ] Type
    - [cty] Content Type
    Not implemented:
    - [x5u] X.509 URL
    - [x5c] X.509 Certficate Chain
    - [crit] Critical

    {{: https://tools.ietf.org/html/rfc7515#section-4.1 } Link to RFC }
    *)

  val make_header : ?typ:string -> Jwk.Pub.t -> t
  (**
  [make_header jwk] creates a header with [typ], [kid] and [alg] set based on the public JWK
  *)

  val of_string : string -> (t, [> `Msg of string ]) result

  val to_string : t -> (string, [> `Msg of string ]) result

  val to_json : t -> Yojson.Safe.t

  val of_json : Yojson.Safe.t -> (t, [> `Msg of string ]) result
end

(**
  {1 JSON Web Signature}

  {{: https://tools.ietf.org/html/rfc7515 } Link to RFC }
*)
module Jws : sig
  type signature = string

  type t = { header : Header.t; payload : string; signature : signature }

  val of_string : string -> (t, [> `Msg of string ]) result

  val to_string : t -> (string, [> `Msg of string ]) result

  val validate : jwk:Jwk.Pub.t -> t -> (t, [> `Msg of string ]) result
  (**
  [validate jwk t] validates the signature
  *)

  val sign :
    header:Header.t ->
    payload:string ->
    Jwk.Priv.t ->
    (t, [> `Msg of string ]) result
  (**
  [sign header payload priv] creates a signed JWT from [header] and [payload]

  We will start using a private JWK instead of a Mirage_crypto_pk.Rsa.priv soon
  *)
end

(**
{1 JSON Web Token}
*)
module Jwt : sig
  type payload = Yojson.Safe.t

  type claim = string * Yojson.Safe.t

  val empty_payload : payload

  type t = { header : Header.t; payload : payload; signature : Jws.signature }

  val add_claim : string -> Yojson.Safe.t -> payload -> payload

  val to_string : t -> (string, [> `Msg of string ]) result

  val of_string : string -> (t, [> `Msg of string ]) result

  val to_jws : t -> Jws.t

  val of_jws : Jws.t -> t

  val validate :
    jwk:Jwk.Pub.t -> t -> (t, [> `Expired | `Msg of string ]) result
  (**
  [validate jwk t] checks if the JWT is valid and then calls Jws.validate to validate the signature
  *)

  val sign :
    header:Header.t ->
    payload:payload ->
    Jwk.Priv.t ->
    (t, [> `Msg of string ]) result
  (**
  [sign header payload priv] creates a signed JWT from [header] and [payload]

  We will start using a private JWK instead of a Mirage_crypto_pk.Rsa.priv soon
  *)
end
