type t = {keys: list(Jwk.Pub.t)};

let to_json: t => Yojson.Safe.t =
  t => {
    let keys_json = List.map(Jwk.Pub.to_yojson, t.keys);
    `Assoc([("keys", `List(keys_json))]);
  };

let of_json = json => {
  keys:
    json
    |> Yojson.Safe.Util.member("keys")
    |> Yojson.Safe.Util.to_list
    |> List.map(Jwk.Pub.of_yojson)
    |> List.filter_map(
         fun
         | Ok(k) => Some(k)
         | _ => None,
       ),
};

let of_string = str => Yojson.Safe.from_string(str) |> of_json;

let to_string = t => to_json(t) |> Yojson.Safe.to_string;
