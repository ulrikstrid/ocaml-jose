open Utils

type algorithm = [ `RS256 | `none | `Unknown ]

type t = {
  alg : algorithm;
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
  { empty_header with alg = `RS256; typ; kid = Some jwk.kid }

module Json = Yojson.Safe.Util

let alg_to_yojson alg =
  (match alg with `RS256 -> "RS256" | `none -> "none" | _ -> "unknown")
  |> fun a -> `String a

let alg_of_yojson alg =
  Yojson.Safe.Util.to_string alg |> function
  | "RS256" -> `RS256
  | "none" -> `none
  | _ -> `Unknown

let of_json json =
  try
    Ok
      {
        alg = json |> Json.member "alg" |> alg_of_yojson;
        jku = json |> Json.member "jku" |> Json.to_string_option;
        jwk = json |> Json.member "jwk" |> Jwk.Pub.of_json |> CCResult.to_opt;
        kid = json |> Json.member "kid" |> Json.to_string_option;
        x5t = json |> Json.member "x5t" |> Json.to_string_option;
        x5t256 = json |> Json.member "x5t#256" |> Json.to_string_option;
        typ = json |> Json.member "typ" |> Json.to_string_option;
        cty = json |> Json.member "cty" |> Json.to_string_option;
      }
  with Json.Type_error (s, _) -> Error (`Msg s)

let to_yojson_string_opt key value =
  match value with Some s -> Some (key, `String s) | None -> None

let to_json t =
  let values =
    [
      to_yojson_string_opt "typ" t.typ;
      Some ("alg", alg_to_yojson t.alg);
      to_yojson_string_opt "jku" t.jku;
      CCOpt.map Jwk.Pub.to_json t.jwk |> CCOpt.map (fun jwk -> ("jwk", jwk));
      to_yojson_string_opt "kid" t.kid;
      to_yojson_string_opt "x5t" t.x5t;
      to_yojson_string_opt "x5t#256" t.x5t256;
      to_yojson_string_opt "cty" t.cty;
    ]
  in
  `Assoc (CCList.filter_map (fun x -> x) values)

let of_string header_str =
  RBase64.base64_url_decode header_str
  |> RResult.flat_map (fun decoded_header ->
         Yojson.Safe.from_string decoded_header |> of_json)

let to_string header =
  to_json header |> Yojson.Safe.to_string |> RBase64.base64_url_encode
