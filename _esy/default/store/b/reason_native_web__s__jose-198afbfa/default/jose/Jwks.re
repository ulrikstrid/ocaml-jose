type t = {keys: list(Jwk.Pub.t)};

let to_json: t => Yojson.Basic.t =
  t => {
    let keys_json = List.map(Jwk.Pub.to_json, t.keys);
    `Assoc([("keys", `List(keys_json))]);
  };

let from_json = json => {
  keys:
    json
    |> Yojson.Basic.Util.member("keys")
    |> Yojson.Basic.Util.to_list
    |> List.map(Jwk.Pub.from_json),
};

let from_string = str => Yojson.Basic.from_string(str) |> from_json;
