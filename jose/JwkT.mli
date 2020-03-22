type priv_jwk

type pub_jwk

type typ = [ `Priv | `Pub ]

type use = [ `Sign | `Encode ]
(** The "use" (public key use) parameter identifies the intended use of
   the public key.  The "use" parameter is employed to indicate whether
   a public key is used for encrypting data or verifying the signature
   on data. 
   
   {{:  https://tools.ietf.org/html/rfc7517#section-4.2 } Link to RFC }
   *)

type 'typ oct = {
  kty : Jwa.kty;
  alg : Jwa.alg;  (** `oct *)
  kid : string;  (** `HS256 *)
  k : string;
}

type 'typ rsa = {
  alg : Jwa.alg;  (** `RSA *)
  kty : Jwa.kty;  (** `RS256 *)
  use : use option;  (** only avaialble in public *)
  n : string;
  e : string;
  d : string;  (** only avaialble in private *)
  p : string;  (** only avaialble in private *)
  q : string;  (** only avaialble in private *)
  dp : string;  (** only avaialble in private *)
  dq : string;  (** only avaialble in private *)
  qi : string;  (** only avaialble in private *)
  kid : string;
  x5t : string option;
}

type 'typ t = OCT of 'typ oct | RSA of 'typ rsa

val pub_to_json : pub_jwk t -> Yojson.Safe.t

val priv_to_json : priv_jwk t -> Yojson.Safe.t

val get_alg : 'typ t -> Jwa.alg
val get_kid : 'typ t -> string
val get_kty : 'typ t -> Jwa.kty
