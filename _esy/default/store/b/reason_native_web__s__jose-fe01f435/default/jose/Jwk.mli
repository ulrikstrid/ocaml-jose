module Pub : sig
  type t = {
    alg : string option;
    kty : string;
    use : string option;
    n : string;
    e : string;
    kid : string;
    x5t : string option;
  }

  val empty : t

  val to_pub : t -> (Nocrypto.Rsa.pub, [ `Msg of string ]) result

  val of_pub : Nocrypto.Rsa.pub -> (t, [ `Msg of string ]) result

  val of_pub_pem : string -> (t, [ `Msg of string ]) result

  val to_pub_pem : t -> (string, [ `Msg of string ]) result

  val to_json : t -> Yojson.Basic.t

  val from_json : Yojson.Basic.t -> t

  val from_string : string -> t
end

module Priv : sig
  type t = {
    kty : string;
    n : string;
    e : string;
    d : string;
    p : string;
    q : string;
    dp : string;
    dq : string;
    qi : string;
    alg : string option;
    kid : string;
  }

  val of_priv : Nocrypto.Rsa.priv -> (t, [ `Msg of string ]) result

  val to_priv : t -> (Nocrypto.Rsa.priv, [ `Msg of string ]) result

  val of_priv_pem : string -> (t, [ `Msg of string ]) result

  val to_priv_pem : t -> (string, [ `Msg of string ]) result
end
