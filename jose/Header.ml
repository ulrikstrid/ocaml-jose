open Utils

type t = {
  alg : Jwa.alg;
  jwk : Jwk.public Jwk.t option;
  kid : string option;
  x5t : string option;
  x5t256 : string option;
  typ : string option;
  cty : string option;
  enc : Jwa.enc option;
  extra : (string * Yojson.Safe.t) list option;
}

(* TODO: This is probably very slow *)
let remove_supported (l : (string * Yojson.Safe.t) list) =
  l |> List.remove_assoc "alg" |> List.remove_assoc "jwk"
  |> List.remove_assoc "kid" |> List.remove_assoc "x5t"
  |> List.remove_assoc "x5t#256"
  |> List.remove_assoc "typ" |> List.remove_assoc "cty"
  |> List.remove_assoc "enc"

let make_header ?typ ?alg ?enc ?(extra = []) ?(jwk_header = false)
    (jwk : Jwk.priv Jwk.t) =
  let alg =
    match alg with
    | Some alg -> alg
    | None -> (
        match jwk with
        | Jwk.Rsa_priv _ -> `RS256
        | Jwk.Oct _ -> `HS256
        | Jwk.Es256_priv _ -> `ES256
        | Jwk.Es384_priv _ -> `ES384
        | Jwk.Es512_priv _ -> `ES512
        | Jwk.Ed25519_priv _ -> `EdDSA)
  in
  let kid =
    match List.assoc_opt "kid" extra with
    | Some kid -> Some (Yojson.Safe.Util.to_string kid)
    | None -> Jwk.get_kid jwk
  in
  let extra = remove_supported extra in
  {
    alg;
    jwk = (if jwk_header then Some (Jwk.pub_of_priv jwk) else None);
    kid;
    x5t = None;
    x5t256 = None;
    typ;
    cty = None;
    enc;
    extra = (match extra with [] -> None | extra -> Some extra);
  }

module Json = Yojson.Safe.Util

let get_extra_headers (json : Yojson.Safe.t) =
  match json with
  | `Assoc vals -> (
      let extra = remove_supported vals in
      match extra with [] -> None | extra -> Some extra)
  | _ -> None (* TODO: raise here? *)

let of_json json =
  try
    Ok
      {
        alg = json |> Json.member "alg" |> Jwa.alg_of_json;
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
        extra = get_extra_headers json;
      }
  with Json.Type_error (s, _) -> Error (`Msg s)

let to_json t =
  let values =
    [
      RJson.to_json_string_opt "typ" t.typ;
      Some ("alg", Jwa.alg_to_json t.alg);
      RJson.to_json_string_opt "kid" t.kid;
      U_Opt.map Jwk.to_pub_json t.jwk |> U_Opt.map (fun jwk -> ("jwk", jwk));
      RJson.to_json_string_opt "x5t" t.x5t;
      RJson.to_json_string_opt "x5t#256" t.x5t256;
      RJson.to_json_string_opt "cty" t.cty;
      t.enc
      |> U_Opt.map Jwa.enc_to_string
      |> U_Opt.map (fun enc -> ("enc", `String enc));
    ]
  in
  let extra = Option.value ~default:[] t.extra in
  `Assoc (U_List.filter_map (fun x -> x) values @ extra)

let of_string header_str =
  U_Base64.url_decode header_str
  |> U_Result.flat_map (fun decoded_header ->
         Yojson.Safe.from_string decoded_header |> of_json)

let to_string header =
  to_json header |> Yojson.Safe.to_string |> U_Base64.url_encode_string
