open Utils

type t = {
  alg : Jwa.alg;
      (** Algorithm Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.1} RFC 7515
            §4.1.1},
          {{:https://www.rfc-editor.org/info/rfc7516/#section-4.1.1} RFC 7516
           §4.1.1}) *)
  jwk : Jwk.public Jwk.t option;
      (** JSON Web Key Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.3} RFC 7515
            §4.1.3}, {{:https://www.rfc-editor.org/info/rfc7517} RFC 7517}) *)
  kid : string option;
      (** Key ID Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.4} RFC 7515
            §4.1.4},
          {{:https://www.rfc-editor.org/info/rfc7517/#section-4.5} RFC 7517
           §4.5}) *)
  epk : Jwk.public Jwk.t option;
      (** Ephemeral Public Key Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.6.1.1} RFC 7518
            §4.6.1.1}) *)
  apu : string option;
      (** Agreement PartyUInfo Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.6.1.2} RFC 7518
            §4.6.1.2}) *)
  apv : string option;
      (** Agreement PartyVInfo Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7518/#section-4.6.1.3} RFC 7518
            §4.6.1.3}) *)
  x5t : string option;
      (** X.509 Certificate SHA-1 Thumbprint
          ({{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.7} RFC 7515
            §4.1.7},
          {{:https://www.rfc-editor.org/info/rfc7517/#section-4.8} RFC 7517
           §4.8}) *)
  x5t256 : string option;
      (** X.509 Certificate SHA-256 Thumbprint
          ({{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.8} RFC 7515
            §4.1.8},
          {{:https://www.rfc-editor.org/info/rfc7517/#section-4.9} RFC 7517
           §4.9}) *)
  typ : string option;
      (** Type Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.9} RFC 7515
            §4.1.9},
          {{:https://www.rfc-editor.org/info/rfc7519/#section-5.1} RFC 7519
           §5.1}) *)
  cty : string option;
      (** Content Type Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.10} RFC 7515
            §4.1.10}) *)
  enc : Jwa.enc option;
      (** Encryption Algorithm Header Parameter
          ({{:https://www.rfc-editor.org/info/rfc7516/#section-4.1.2} RFC 7516
            §4.1.2},
          {{:https://www.rfc-editor.org/info/rfc7518/#section-5.1} RFC 7518
           §5.1}) *)
  extra : (string * Yojson.Safe.t) list;
      (** Additional custom/unregistered header parameters *)
}

let remove_supported (l : (string * Yojson.Safe.t) list) =
  List.filter
    (fun (key, _) ->
      match key with
      | "alg" | "jwk" | "kid" | "epk" | "apu" | "apv" | "x5t" | "x5t#S256"
      | "typ" | "cty" | "enc" ->
          false
      | _ -> true)
    l

let make_header ?typ ?alg ?enc ?(extra = []) ?(jwk_header = false) ?epk ?apu
    ?apv (jwk : Jwk.priv Jwk.t) =
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
        | Jwk.Ed25519_priv _ -> `Ed25519)
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
    epk;
    apu;
    apv;
    x5t = None;
    x5t256 = None;
    typ;
    cty = None;
    enc;
    extra;
  }

module Json = Yojson.Safe.Util

let get_extra_headers (json : Yojson.Safe.t) =
  match json with
  | `Assoc vals -> (
      let extra = remove_supported vals in
      match extra with [] -> [] | extra -> extra)
  | _ -> [] (* TODO: raise here? *)

let of_json json =
  try
    Ok
      {
        alg = json |> Json.member "alg" |> Jwa.alg_of_json;
        jwk =
          json |> Json.member "jwk"
          |> Json.to_option (fun jwk_json ->
              Jwk.of_pub_json jwk_json |> Result.to_option)
          |> Option.join;
        kid = json |> Json.member "kid" |> Json.to_string_option;
        epk =
          json |> Json.member "epk"
          |> Json.to_option (fun jwk_json ->
              Jwk.of_pub_json jwk_json |> Result.to_option)
          |> Option.join;
        apu = json |> Json.member "apu" |> Json.to_string_option;
        apv = json |> Json.member "apv" |> Json.to_string_option;
        x5t = json |> Json.member "x5t" |> Json.to_string_option;
        x5t256 = json |> Json.member "x5t#256" |> Json.to_string_option;
        typ = json |> Json.member "typ" |> Json.to_string_option;
        cty = json |> Json.member "cty" |> Json.to_string_option;
        enc =
          json |> Json.member "enc" |> Json.to_string_option
          |> Option.map Jwa.enc_of_string;
        extra = get_extra_headers json;
      }
  with Json.Type_error (s, _) -> Error (`Msg s)

let to_json t =
  let values =
    [
      RJson.to_json_string_opt "typ" t.typ;
      Some ("alg", Jwa.alg_to_json t.alg);
      RJson.to_json_string_opt "kid" t.kid;
      Option.map Jwk.to_pub_json t.jwk |> Option.map (fun jwk -> ("jwk", jwk));
      Option.map Jwk.to_pub_json t.epk |> Option.map (fun epk -> ("epk", epk));
      RJson.to_json_string_opt "apu" t.apu;
      RJson.to_json_string_opt "apv" t.apv;
      RJson.to_json_string_opt "x5t" t.x5t;
      RJson.to_json_string_opt "x5t#256" t.x5t256;
      RJson.to_json_string_opt "cty" t.cty;
      t.enc
      |> Option.map Jwa.enc_to_string
      |> Option.map (fun enc -> ("enc", `String enc));
    ]
  in
  `Assoc (List.filter_map Fun.id values @ t.extra)

let of_string header_str =
  let s = U_Base64.url_decode header_str in
  Result.bind s (fun decoded_header ->
      Yojson.Safe.from_string decoded_header |> of_json)

let to_string header =
  to_json header |> Yojson.Safe.to_string |> U_Base64.url_encode_string
