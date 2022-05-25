open Utils

type t = {
  alg : Jwa.alg;
  jku : string option;
  jwk : Jwk.public Jwk.t option;
  kid : string option;
  x5t : string option;
  x5t256 : string option;
  typ : string option;
  cty : string option;
  enc : Jwa.enc option;
}

let make_header ?typ ?alg ?enc (jwk : Jwk.priv Jwk.t) =
  let alg =
    match alg with
    | Some alg -> alg
    | None -> (
        match jwk with
        | Jwk.Rsa_priv _ -> `RS256
        | Jwk.Oct _ -> `HS256
        | Jwk.Es256_priv _ -> `ES256
        | Jwk.Es512_priv _ -> `ES512)
  in
  {
    alg;
    jku = None;
    jwk = None;
    kid = Jwk.get_kid jwk;
    x5t = None;
    x5t256 = None;
    typ;
    cty = None;
    enc;
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
                 Jwk.of_pub_json jwk_json |> U_Result.to_opt)
          |> U_Opt.flatten;
        kid = json |> Json.member "kid" |> Json.to_string_option;
        x5t = json |> Json.member "x5t" |> Json.to_string_option;
        x5t256 = json |> Json.member "x5t#256" |> Json.to_string_option;
        typ = json |> Json.member "typ" |> Json.to_string_option;
        cty = json |> Json.member "cty" |> Json.to_string_option;
        enc =
          json |> Json.member "enc" |> Json.to_string_option
          |> U_Opt.map Jwa.enc_of_string;
      }
  with Json.Type_error (s, _) -> Error (`Msg s)

let to_json t =
  let values =
    [
      RJson.to_json_string_opt "typ" t.typ;
      Some ("alg", Jwa.alg_to_json t.alg);
      RJson.to_json_string_opt "jku" t.jku;
      U_Opt.map Jwk.to_pub_json t.jwk |> U_Opt.map (fun jwk -> ("jwk", jwk));
      RJson.to_json_string_opt "kid" t.kid;
      RJson.to_json_string_opt "x5t" t.x5t;
      RJson.to_json_string_opt "x5t#256" t.x5t256;
      RJson.to_json_string_opt "cty" t.cty;
      t.enc |> U_Opt.map Jwa.enc_to_string
      |> U_Opt.map (fun enc -> ("enc", `String enc));
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let of_string header_str =
  U_Base64.url_decode header_str
  |> U_Result.flat_map (fun decoded_header ->
         Yojson.Safe.from_string decoded_header |> of_json)

let to_string header =
  to_json header |> Yojson.Safe.to_string |> U_Base64.url_encode_string
