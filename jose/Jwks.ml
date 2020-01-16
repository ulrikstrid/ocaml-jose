type t = { keys : Jwk.Pub.t list }

let to_json t =
  let keys_json = List.map Jwk.Pub.to_json t.keys in
  `Assoc [ ("keys", `List keys_json) ]

let of_json json =
  {
    keys =
      json
      |> Yojson.Safe.Util.member "keys"
      |> Yojson.Safe.Util.to_list |> List.map Jwk.Pub.of_json
      |> Utils.RList.filter_map Utils.RResult.to_opt;
  }

let to_string t = to_json t |> Yojson.Safe.to_string

let of_string str = Yojson.Safe.from_string str |> of_json

let find_key jwks kid =
  Utils.RList.find_opt
    (fun (jwk : Jwk.Pub.t) -> Jwk.Pub.get_kid jwk = kid)
    jwks.keys
