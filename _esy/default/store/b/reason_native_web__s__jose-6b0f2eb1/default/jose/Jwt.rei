type header;

let make_header: Jwk.Pub.t => header;

type payload = Yojson.Basic.t;
type claim = (string, Yojson.Basic.t);

let empty_payload: payload;

type signature;

type t;

let add_claim: (string, Yojson.Basic.t, payload) => payload;

let sign:
  (header, Nocrypto.Rsa.priv, payload) => result(t, [ | `Msg(string)]);

let to_string: t => string;
let from_string: string => result(t, [ | `Msg(string)]);

let verify: (~jwks: list(Jwk.Pub.t), t) => result(t, [ | `Msg(string)]);
