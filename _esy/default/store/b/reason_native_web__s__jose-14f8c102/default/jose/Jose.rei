module Jwk: {
  module Pub: {
    type t = {
      alg: option(string),
      kty: string,
      use: option(string),
      n: string,
      e: string,
      kid: string,
      x5t: option(string),
    };

    let empty: t;

    let to_pub: t => result(Nocrypto.Rsa.pub, [ | `Msg(string)]);

    let of_pub: Nocrypto.Rsa.pub => result(t, [ | `Msg(string)]);

    let of_pub_pem: string => result(t, [ | `Msg(string)]);

    let to_pub_pem: t => result(string, [ | `Msg(string)]);

    let to_json: t => Yojson.Basic.t;

    let from_json: Yojson.Basic.t => t;

    let from_string: string => t;
  };

  module Priv: {
    type t = {
      kty: string,
      n: string,
      e: string,
      d: string,
      p: string,
      q: string,
      dp: string,
      dq: string,
      qi: string,
      alg: option(string),
      kid: string,
    };

    let of_priv: Nocrypto.Rsa.priv => result(t, [ | `Msg(string)]);

    let to_priv: t => result(Nocrypto.Rsa.priv, [ | `Msg(string)]);

    let of_priv_pem: string => result(t, [ | `Msg(string)]);

    let to_priv_pem: t => result(string, [ | `Msg(string)]);
  };
};
