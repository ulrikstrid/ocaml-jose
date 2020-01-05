type t = {keys: list(Jwk.Pub.t)};

let to_json: t => Yojson.Basic.t;

let from_json: Yojson.Basic.t => t;

let from_string: string => t;
