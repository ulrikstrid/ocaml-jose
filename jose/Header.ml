open Utils

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

let empty_header =
  {
    alg = `none;
    jku = None;
    jwk = None;
    kid = None;
    x5t = None;
    x5t256 = None;
    typ = None;
    cty = None;
  }

let make_header ?typ (jwk : Jwk.Pub.t) =
  { empty_header with alg = `RS256; typ; kid = Some (Jwk.Pub.get_kid jwk) }

module Json = Yojson.Safe.Util

let of_json json =
  try
    Ok
      {
        alg = json |> Json.member "alg" |> Jwa.alg_of_json;
        jku = json |> Json.member "jku" |> Json.to_string_option;
        jwk =
          json |> Json.member "jwk"
          |> Json.to_option (fun jwk_json ->
                 Jwk.Pub.of_json jwk_json |> RResult.to_opt)
          |> ROpt.flatten;
        kid = json |> Json.member "kid" |> Json.to_string_option;
        x5t = json |> Json.member "x5t" |> Json.to_string_option;
        x5t256 = json |> Json.member "x5t#256" |> Json.to_string_option;
        typ = json |> Json.member "typ" |> Json.to_string_option;
        cty = json |> Json.member "cty" |> Json.to_string_option;
      }
  with Json.Type_error (s, _) -> Error (`Msg s)

let to_json t =
  let values =
    [
      RJson.to_json_string_opt "typ" t.typ;
      Some ("alg", Jwa.alg_to_json t.alg);
      RJson.to_json_string_opt "jku" t.jku;
      ROpt.map Jwk.Pub.to_json t.jwk |> ROpt.map (fun jwk -> ("jwk", jwk));
      RJson.to_json_string_opt "kid" t.kid;
      RJson.to_json_string_opt "x5t" t.x5t;
      RJson.to_json_string_opt "x5t#256" t.x5t256;
      RJson.to_json_string_opt "cty" t.cty;
    ]
  in
  `Assoc (RList.filter_map (fun x -> x) values)

let of_string header_str =
  RBase64.base64_url_decode header_str
  |> RResult.flat_map (fun decoded_header ->
         Yojson.Safe.from_string decoded_header |> of_json)

let to_string header =
  to_json header |> Yojson.Safe.to_string |> RBase64.base64_url_encode
