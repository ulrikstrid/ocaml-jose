open Utils

type t = {
  alg : Jwa.alg;
  jku : string option;
  jwk : Jwk.public Jwk.t option;
  kid : string;
  x5t : string option;
  x5t256 : string option;
  typ : string option;
  cty : string option;
  enc : Jwa.enc option;
}

let make_header ?typ (jwk : Jwk.priv Jwk.t) =
  let alg = match jwk with Jwk.Rsa_priv _ -> `RS256 | Jwk.Oct _ -> `HS256 in
  {
    alg;
    jku = None;
    jwk = None;
    kid = Jwk.get_kid jwk;
    x5t = None;
    x5t256 = None;
    typ;
    cty = None;
    enc = None;
  }

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
                 Jwk.of_pub_json jwk_json |> RResult.to_opt)
          |> ROpt.flatten;
        kid = json |> Json.member "kid" |> Json.to_string;
        x5t = json |> Json.member "x5t" |> Json.to_string_option;
        x5t256 = json |> Json.member "x5t#256" |> Json.to_string_option;
        typ = json |> Json.member "typ" |> Json.to_string_option;
        cty = json |> Json.member "cty" |> Json.to_string_option;
        enc =
          json |> Json.member "enc" |> Json.to_string_option
          |> ROpt.map Jwa.enc_of_string;
      }
  with Json.Type_error (s, _) -> Error (`Msg s)

let to_json t =
  let values =
    [
      RJson.to_json_string_opt "typ" t.typ;
      Some ("alg", Jwa.alg_to_json t.alg);
      RJson.to_json_string_opt "jku" t.jku;
      ROpt.map Jwk.to_pub_json t.jwk |> ROpt.map (fun jwk -> ("jwk", jwk));
      Some ("kid", `String t.kid);
      RJson.to_json_string_opt "x5t" t.x5t;
      RJson.to_json_string_opt "x5t#256" t.x5t256;
      RJson.to_json_string_opt "cty" t.cty;
      t.enc |> ROpt.map Jwa.enc_to_string
      |> ROpt.map (fun enc -> ("enc", `String enc));
    ]
  in
  `Assoc (RList.filter_map (fun x -> x) values)

let of_string header_str =
  RBase64.url_decode header_str
  |> RResult.flat_map (fun decoded_header ->
         Yojson.Safe.from_string decoded_header |> of_json)

let to_string header =
  to_json header |> Yojson.Safe.to_string |> RBase64.url_encode
