type t = { keys : Jwk.public Jwk.t list }

let to_json t =
  let keys_json = List.map Jwk.to_pub_json t.keys in
  `Assoc [ ("keys", `List keys_json) ]

let of_json json =
  {
    keys =
      json
      |> Yojson.Safe.Util.member "keys"
      |> Yojson.Safe.Util.to_list |> List.map Jwk.of_pub_json
      |> Utils.RList.filter_map Utils.RResult.to_opt;
  }

let to_string t = to_json t |> Yojson.Safe.to_string

let of_string str = Yojson.Safe.from_string str |> of_json

let find_key jwks kid =
  Utils.RList.find_opt
    (fun (jwk : Jwk.public Jwk.t) ->
      Jwk.get_kid jwk
      |> Utils.RResult.map (fun k -> k = kid)
      |> Utils.RResult.get_default ~default:false)
    jwks.keys
