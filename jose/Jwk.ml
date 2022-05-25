open Utils

module Util = struct
  let get_JWK_component ?(pad = false) e : string =
    Z.to_bits e |> U_String.rev |> U_String.trim_leading_null
    |> U_Base64.url_encode_string ~pad

  let get_component ?(pad = false) e =
    U_Base64.url_decode ~pad e
    |> U_Result.map (fun x ->
           U_String.pad 8 ~c:'\000' x |> U_String.rev |> Z.of_bits)

  let kid_of_json json =
    Yojson.Safe.to_string json |> Cstruct.of_string
    |> Mirage_crypto.Hash.SHA256.digest |> Cstruct.to_bytes |> Bytes.to_string
    |> U_Base64.url_encode_string

  let get_JWK_x5t fingerprint =
    fingerprint |> Cstruct.to_bytes |> Bytes.to_string
    |> U_Base64.url_encode ~len:20

  let get_ES256_x_y key =
    let point = Mirage_crypto_ec.P256.Dsa.pub_to_cstruct key in
    let x_cs, y_cs = Cstruct.(split (shift point 1) 32) in
    let x = x_cs |> Cstruct.to_string |> U_Base64.url_encode_string in
    let y = y_cs |> Cstruct.to_string |> U_Base64.url_encode_string in
    (x, y)

  let make_ES256_of_x_y (x, y) =
    let x = U_Base64.url_decode x |> U_Result.map Cstruct.of_string in
    let y = U_Base64.url_decode y |> U_Result.map Cstruct.of_string in
    U_Result.both x y
    |> U_Result.map (fun (x, y) ->
           let four = Cstruct.create 1 in
           Cstruct.set_uint8 four 0 4;
           let point = Cstruct.concat [ four; x; y ] in
           let k = Mirage_crypto_ec.P256.Dsa.pub_of_cstruct point in
           k |> Result.get_ok)

  let get_ES512_x_y key =
    let point = Mirage_crypto_ec.P521.Dsa.pub_to_cstruct key in
    let x_cs, y_cs = Cstruct.(split (shift point 1) 66) in
    let x = x_cs |> Cstruct.to_string |> U_Base64.url_encode_string in
    let y = y_cs |> Cstruct.to_string |> U_Base64.url_encode_string in
    (x, y)

  let make_ES512_of_x_y (x, y) =
    let x = U_Base64.url_decode x |> U_Result.map Cstruct.of_string in
    let y = U_Base64.url_decode y |> U_Result.map Cstruct.of_string in
    U_Result.both x y
    |> U_Result.map (fun (x, y) ->
           let four = Cstruct.create 1 in
           Cstruct.set_uint8 four 0 4;
           let point = Cstruct.concat [ four; x; y ] in
           let k = Mirage_crypto_ec.P521.Dsa.pub_of_cstruct point in
           k |> Result.get_ok)
end

type use = [ `Sig | `Enc | `Unsupported of string ]

let use_to_string use =
  match use with `Sig -> "sig" | `Enc -> "enc" | `Unsupported str -> str

let use_of_string use =
  match use with "sig" -> `Sig | "enc" -> `Enc | str -> `Unsupported str

let alg_of_use_and_kty ?(use : use = `Sig) (kty : Jwa.kty) =
  match (use, kty) with
  | `Sig, `oct -> `HS256
  | `Sig, `RSA -> `RS256
  | `Sig, `EC -> `ES512
  | `Enc, `RSA -> `RSA_OAEP
  | `Enc, `oct -> `Unsupported "encryption with oct is not supported yet"
  | _, `EC -> `Unsupported "Eliptic curves are not supported yet"
  | `Unsupported u, _ -> `Unsupported ("We don't know what to do with use: " ^ u)
  | _, `Unsupported k -> `Unsupported ("We don't know what to do with kty: " ^ k)

let use_of_alg (alg : Jwa.alg) =
  match alg with
  | `HS256 -> `Sig
  | `RS256 -> `Sig
  | `ES256 -> `Sig
  | `ES512 -> `Sig
  | `RSA_OAEP -> `Enc
  | `RSA1_5 -> `Enc
  | `None -> `Unsupported "none"
  | `Unsupported str -> `Unsupported str

type public = Public
type priv = Private

type 'key jwk = {
  alg : Jwa.alg;
  kty : Jwa.kty;
  use : use;
  kid : string option;
  key : 'key;
}

type oct = string jwk
type priv_rsa = Mirage_crypto_pk.Rsa.priv jwk
type pub_rsa = Mirage_crypto_pk.Rsa.pub jwk
type priv_es256 = Mirage_crypto_ec.P256.Dsa.priv jwk
type pub_es256 = Mirage_crypto_ec.P256.Dsa.pub jwk
type priv_es512 = Mirage_crypto_ec.P521.Dsa.priv jwk
type pub_es512 = Mirage_crypto_ec.P521.Dsa.pub jwk

type 'a t =
  | Oct : oct -> 'a t
  | Rsa_priv : priv_rsa -> priv t
  | Rsa_pub : pub_rsa -> public t
  | Es256_priv : priv_es256 -> priv t
  | Es256_pub : pub_es256 -> public t
  | Es512_priv : priv_es512 -> priv t
  | Es512_pub : pub_es512 -> public t

let get_alg (type a) (t : a t) : Jwa.alg =
  match t with
  | Rsa_priv rsa -> rsa.alg
  | Rsa_pub rsa -> rsa.alg
  | Es256_priv es -> es.alg
  | Es256_pub es -> es.alg
  | Es512_priv es -> es.alg
  | Es512_pub es -> es.alg
  | Oct oct -> oct.alg

let get_kty (type a) (t : a t) =
  match t with
  | Rsa_priv _ -> `RSA
  | Rsa_pub _ -> `RSA
  | Es256_priv _ -> `EC
  | Es256_pub _ -> `EC
  | Es512_priv _ -> `EC
  | Es512_pub _ -> `EC
  | Oct _ -> `oct

let get_kid (type a) (t : a t) =
  match t with
  | Rsa_priv rsa -> rsa.kid
  | Rsa_pub rsa -> rsa.kid
  | Es256_priv es -> es.kid
  | Es256_pub es -> es.kid
  | Es512_priv es -> es.kid
  | Es512_pub es -> es.kid
  | Oct oct -> oct.kid

let make_kid (type a) (t : a t) =
  let kid =
    match t with
    | Rsa_priv rsa_priv ->
        let e = Util.get_JWK_component rsa_priv.key.e in
        let n = Util.get_JWK_component rsa_priv.key.n in
        `Assoc [ ("e", `String e); ("kty", `String "RSA"); ("n", `String n) ]
        |> Util.kid_of_json
    | Rsa_pub rsa_pub ->
        let e = Util.get_JWK_component rsa_pub.key.e in
        let n = Util.get_JWK_component rsa_pub.key.n in
        `Assoc [ ("e", `String e); ("kty", `String "RSA"); ("n", `String n) ]
        |> Util.kid_of_json
    | Es256_priv es ->
        let x, y =
          Util.get_ES256_x_y (Mirage_crypto_ec.P256.Dsa.pub_of_priv es.key)
        in
        `Assoc
          [
            ("crv", `String "P-256");
            ("kty", `String "EC");
            ("x", `String x);
            ("y", `String y);
          ]
        |> Util.kid_of_json
    | Es256_pub es ->
        let x, y = Util.get_ES256_x_y es.key in
        `Assoc
          [
            ("crv", `String "P-256");
            ("kty", `String "EC");
            ("x", `String x);
            ("y", `String y);
          ]
        |> Util.kid_of_json
    | Es512_priv es ->
        let x, y =
          Util.get_ES512_x_y (Mirage_crypto_ec.P521.Dsa.pub_of_priv es.key)
        in
        `Assoc
          [
            ("crv", `String "P-521");
            ("kty", `String "EC");
            ("x", `String x);
            ("y", `String y);
          ]
        |> Util.kid_of_json
    | Es512_pub es ->
        let x, y = Util.get_ES512_x_y es.key in
        `Assoc
          [
            ("crv", `String "P-521");
            ("kty", `String "EC");
            ("x", `String x);
            ("y", `String y);
          ]
        |> Util.kid_of_json
    | Oct oct ->
        `Assoc [ ("k", `String oct.key); ("kty", `String "oct") ]
        |> Util.kid_of_json
  in
  Some kid

let make_oct ?(use : use = `Sig) (str : string) : 'a t =
  (* Should we make this just return a result intead? *)
  let key = U_Base64.url_encode_string str in
  let jwk = { kty = `oct; use; alg = `HS256; key; kid = None } in
  Oct { jwk with kid = make_kid (Oct jwk) }

let make_priv_rsa ?(use : use = `Sig) (rsa_priv : Mirage_crypto_pk.Rsa.priv) :
    priv t =
  let kty : Jwa.kty = `RSA in
  let alg = alg_of_use_and_kty ~use kty in
  let jwk = { alg; kty; use; key = rsa_priv; kid = None } in
  Rsa_priv { jwk with kid = make_kid (Rsa_priv jwk) }

let make_priv_es256 ?(use : use = `Sig)
    (es256_priv : Mirage_crypto_ec.P256.Dsa.priv) : priv t =
  let kty : Jwa.kty = `EC in
  let alg = `ES256 in
  let jwk = { alg; kty; use; key = es256_priv; kid = None } in
  Es256_priv { jwk with kid = make_kid (Es256_priv jwk) }

let make_priv_es512 ?(use : use = `Sig)
    (es512_priv : Mirage_crypto_ec.P521.Dsa.priv) : priv t =
  let kty : Jwa.kty = `EC in
  let alg = `ES512 in
  let jwk = { alg; kty; use; key = es512_priv; kid = None } in
  Es512_priv { jwk with kid = make_kid (Es512_priv jwk) }

let make_pub_rsa ?(use : use = `Sig) (rsa_pub : Mirage_crypto_pk.Rsa.pub) :
    public t =
  let kty : Jwa.kty = `RSA in
  let alg = alg_of_use_and_kty ~use kty in
  let jwk = { alg; kty; use; key = rsa_pub; kid = None } in
  Rsa_pub { jwk with kid = make_kid (Rsa_pub jwk) }

let of_pub_pem ?(use : use = `Sig) pem : (public t, [> `Not_rsa ]) result =
  Cstruct.of_string pem |> X509.Public_key.decode_pem
  |> U_Result.flat_map (function
       | `RSA pub_key -> Ok pub_key
       | _ -> Error `Not_rsa)
  |> U_Result.map (make_pub_rsa ~use)

let to_pub_pem (type a) (jwk : a t) =
  match jwk with
  | Rsa_pub rsa ->
      Ok (X509.Public_key.encode_pem (`RSA rsa.key) |> Cstruct.to_string)
  | Rsa_priv rsa ->
      rsa.key |> Mirage_crypto_pk.Rsa.pub_of_priv
      |> (fun key -> X509.Public_key.encode_pem (`RSA key))
      |> Cstruct.to_string |> U_Result.return
  | _ -> Error `Not_rsa

let of_priv_pem ?(use : use = `Sig) pem : (priv t, [> `Not_rsa ]) result =
  Cstruct.of_string pem |> X509.Private_key.decode_pem
  |> U_Result.flat_map (function
       | `RSA priv_key -> Ok (make_priv_rsa ~use priv_key)
       | `P256 priv_key -> Ok (make_priv_es256 ~use priv_key)
       | `P521 priv_key -> Ok (make_priv_es512 ~use priv_key)
       | _ -> Error `Not_rsa)

let to_priv_pem (jwk : priv t) =
  match jwk with
  | Rsa_priv rsa ->
      Ok (X509.Private_key.encode_pem (`RSA rsa.key) |> Cstruct.to_string)
  | _ -> Error `Not_rsa

let oct_to_json (oct : oct) =
  let values =
    [
      Some ("alg", Jwa.alg_to_json oct.alg);
      Some ("kty", `String (Jwa.kty_to_string oct.kty));
      Some ("k", `String oct.key);
      RJson.to_json_string_opt "kid" oct.kid;
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let pub_rsa_to_json pub_rsa =
  (* Should I make this a result? It feels like our well-formed key should
     always be able to become a JSON *)
  let public_key : X509.Public_key.t = `RSA pub_rsa.key in
  let e = Util.get_JWK_component pub_rsa.key.e in
  let n = Util.get_JWK_component pub_rsa.key.n in
  let values =
    [
      Some ("alg", Jwa.alg_to_json pub_rsa.alg);
      Some ("e", `String e);
      Some ("n", `String n);
      Some ("kty", `String (Jwa.kty_to_string pub_rsa.kty));
      RJson.to_json_string_opt "kid" pub_rsa.kid;
      Some ("use", `String (use_to_string pub_rsa.use));
      RJson.to_json_string_opt "x5t"
        (Util.get_JWK_x5t (X509.Public_key.fingerprint ~hash:`SHA1 public_key)
        |> U_Result.to_opt);
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let pub_of_priv_rsa (priv_rsa : priv_rsa) : pub_rsa =
  { priv_rsa with key = Mirage_crypto_pk.Rsa.pub_of_priv priv_rsa.key }

let pub_of_priv_es256 (priv_es256 : priv_es256) : pub_es256 =
  { priv_es256 with key = Mirage_crypto_ec.P256.Dsa.pub_of_priv priv_es256.key }

let pub_of_priv_es512 (priv_es512 : priv_es512) : pub_es512 =
  { priv_es512 with key = Mirage_crypto_ec.P521.Dsa.pub_of_priv priv_es512.key }

let priv_rsa_to_pub_json (priv_rsa : priv_rsa) =
  pub_rsa_to_json (pub_of_priv_rsa priv_rsa)

let priv_rsa_to_priv_json (priv_rsa : priv_rsa) : Yojson.Safe.t =
  (* Should I make this a result? It feels like our well-formed key should
     always be able to become a JSON *)
  let n = Util.get_JWK_component priv_rsa.key.n in
  let e = Util.get_JWK_component priv_rsa.key.e in
  let d = Util.get_JWK_component priv_rsa.key.d in
  let p = Util.get_JWK_component priv_rsa.key.p in
  let q = Util.get_JWK_component priv_rsa.key.q in
  let dp = Util.get_JWK_component priv_rsa.key.dp in
  let dq = Util.get_JWK_component priv_rsa.key.dq in
  let qi = Util.get_JWK_component priv_rsa.key.q' in
  let values =
    [
      Some ("alg", Jwa.alg_to_json priv_rsa.alg);
      Some ("e", `String e);
      Some ("n", `String n);
      Some ("d", `String d);
      Some ("p", `String p);
      Some ("q", `String q);
      Some ("dp", `String dp);
      Some ("dq", `String dq);
      Some ("qi", `String qi);
      Some ("kty", `String (priv_rsa.kty |> Jwa.kty_to_string));
      Some ("use", `String (use_to_string priv_rsa.use));
      RJson.to_json_string_opt "kid" priv_rsa.kid;
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let pub_es256_to_pub_json (pub_es256 : pub_es256) : Yojson.Safe.t =
  let x, y = Util.get_ES256_x_y pub_es256.key in
  let values =
    [
      Some ("alg", Jwa.alg_to_json pub_es256.alg);
      Some ("crv", `String "P-256");
      Some ("x", `String x);
      Some ("y", `String y);
      Some ("kty", `String (pub_es256.kty |> Jwa.kty_to_string));
      Some ("use", `String (use_to_string pub_es256.use));
      RJson.to_json_string_opt "kid" pub_es256.kid;
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let priv_es256_to_pub_json (priv_es256 : priv_es256) : Yojson.Safe.t =
  pub_of_priv_es256 priv_es256 |> pub_es256_to_pub_json

let priv_es256_to_priv_json (priv_es256 : priv_es256) : Yojson.Safe.t =
  let x, y =
    Util.get_ES256_x_y (Mirage_crypto_ec.P256.Dsa.pub_of_priv priv_es256.key)
  in
  let d =
    Mirage_crypto_ec.P256.Dsa.priv_to_cstruct priv_es256.key
    |> Cstruct.to_string |> U_Base64.url_encode_string
  in
  let values =
    [
      Some ("alg", Jwa.alg_to_json priv_es256.alg);
      Some ("crv", `String "P-256");
      Some ("x", `String x);
      Some ("y", `String y);
      Some ("d", `String d);
      Some ("kty", `String (priv_es256.kty |> Jwa.kty_to_string));
      Some ("use", `String (use_to_string priv_es256.use));
      RJson.to_json_string_opt "kid" priv_es256.kid;
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let pub_es512_to_pub_json (pub_es512 : pub_es512) : Yojson.Safe.t =
  let x, y = Util.get_ES512_x_y pub_es512.key in
  let values =
    [
      Some ("alg", Jwa.alg_to_json pub_es512.alg);
      Some ("crv", `String "P-521");
      Some ("x", `String x);
      Some ("y", `String y);
      Some ("kty", `String (pub_es512.kty |> Jwa.kty_to_string));
      Some ("use", `String (use_to_string pub_es512.use));
      RJson.to_json_string_opt "kid" pub_es512.kid;
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let priv_es512_to_pub_json (priv_es512 : priv_es512) : Yojson.Safe.t =
  pub_of_priv_es512 priv_es512 |> pub_es512_to_pub_json

let priv_es512_to_priv_json (priv_es512 : priv_es512) : Yojson.Safe.t =
  let x, y =
    Util.get_ES512_x_y (Mirage_crypto_ec.P521.Dsa.pub_of_priv priv_es512.key)
  in
  let d =
    Mirage_crypto_ec.P521.Dsa.priv_to_cstruct priv_es512.key
    |> Cstruct.to_string |> U_Base64.url_encode_string
  in
  let values =
    [
      Some ("alg", Jwa.alg_to_json priv_es512.alg);
      Some ("crv", `String "P-521");
      Some ("x", `String x);
      Some ("y", `String y);
      Some ("d", `String d);
      Some ("kty", `String (priv_es512.kty |> Jwa.kty_to_string));
      Some ("use", `String (use_to_string priv_es512.use));
      RJson.to_json_string_opt "kid" priv_es512.kid;
    ]
  in
  `Assoc (U_List.filter_map (fun x -> x) values)

let to_pub_json (type a) (jwk : a t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_pub_json rsa
  | Rsa_pub rsa -> pub_rsa_to_json rsa
  | Es256_priv ec -> priv_es256_to_pub_json ec
  | Es256_pub ec -> pub_es256_to_pub_json ec
  | Es512_priv ec -> priv_es512_to_pub_json ec
  | Es512_pub ec -> pub_es512_to_pub_json ec

let to_pub_json_string (type a) (jwk : a t) : string =
  to_pub_json jwk |> Yojson.Safe.to_string

let to_priv_json (jwk : priv t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_priv_json rsa
  | Es256_priv ec -> priv_es256_to_priv_json ec
  | Es512_priv ec -> priv_es512_to_priv_json ec

let to_priv_json_string (jwk : priv t) : string =
  to_priv_json jwk |> Yojson.Safe.to_string

let pub_rsa_of_json json : (public t, 'error) result =
  let module Json = Yojson.Safe.Util in
  try
    let e = json |> Json.member "e" |> Json.to_string |> Util.get_component in
    let n = json |> Json.member "n" |> Json.to_string |> Util.get_component in
    U_Result.both e n
    |> U_Result.flat_map (fun (e, n) -> Mirage_crypto_pk.Rsa.pub ~e ~n)
    |> U_Result.flat_map (fun key ->
           let alg =
             json |> Json.member "alg" |> Json.to_string_option
             |> U_Opt.map Jwa.alg_of_string
           in
           let use =
             json |> Json.member "use" |> Json.to_string_option
             |> U_Opt.map use_of_string
           in
           let kid = json |> Json.member "kid" |> Json.to_string_option in
           let kty = `RSA in
           match (alg, use) with
           | Some alg, Some use -> Ok (Rsa_pub { alg; kty; use; key; kid })
           | Some alg, None ->
               Ok (Rsa_pub { alg; kty; use = use_of_alg alg; key; kid })
           | None, Some use ->
               Ok
                 (Rsa_pub
                    { alg = alg_of_use_and_kty ~use kty; kty; use; key; kid })
           | None, None -> Error `Missing_use_and_alg)
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let priv_rsa_of_json json : (priv t, 'error) result =
  let module Json = Yojson.Safe.Util in
  try
    let e = json |> Json.member "e" |> Json.to_string |> Util.get_component in
    let n = json |> Json.member "n" |> Json.to_string |> Util.get_component in
    let d = json |> Json.member "d" |> Json.to_string |> Util.get_component in
    let p = json |> Json.member "p" |> Json.to_string |> Util.get_component in
    let q = json |> Json.member "q" |> Json.to_string |> Util.get_component in
    let dp = json |> Json.member "dp" |> Json.to_string |> Util.get_component in
    let dq = json |> Json.member "dq" |> Json.to_string |> Util.get_component in
    let qi = json |> Json.member "qi" |> Json.to_string |> Util.get_component in
    U_Result.all8 e n d p q dp dq qi
    |> U_Result.flat_map (fun (e, n, d, p, q, dp, dq, qi) ->
           Mirage_crypto_pk.Rsa.priv ~e ~n ~d ~p ~q ~dp ~dq ~q':qi)
    |> U_Result.flat_map (fun key ->
           let alg =
             json |> Json.member "alg" |> Json.to_string_option
             |> U_Opt.map Jwa.alg_of_string
           in
           let use =
             json |> Json.member "use" |> Json.to_string_option
             |> U_Opt.map use_of_string
           in
           let kid = json |> Json.member "kid" |> Json.to_string_option in
           let kty = `RSA in
           match (alg, use) with
           | Some alg, Some use -> Ok (Rsa_priv { alg; kty; use; key; kid })
           | Some alg, None ->
               Ok (Rsa_priv { alg; kty; use = use_of_alg alg; key; kid })
           | None, Some use ->
               Ok
                 (Rsa_priv
                    { alg = alg_of_use_and_kty ~use kty; kty; use; key; kid })
           | None, None -> Error `Missing_use_and_alg)
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let oct_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg = json |> Json.member "alg" |> Jwa.alg_of_json in
    Ok
      (Oct
         {
           alg;
           kty = `oct;
           (* Shortcut since that is the only thing we handle *)
           use =
             json |> Json.member "use" |> Json.to_string_option
             |> U_Opt.map use_of_string
             |> U_Opt.get_with_default ~default:(use_of_alg alg);
           key = json |> Json.member "k" |> Json.to_string;
           kid = json |> Json.member "kid" |> Json.to_string_option;
         })
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let pub_ec_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg =
      json |> Json.member "alg" |> Json.to_string_option
      |> U_Opt.map Jwa.alg_of_string
    in
    let crv = json |> Json.member "crv" |> Json.to_string in
    let x = json |> Json.member "x" |> Json.to_string in
    let y = json |> Json.member "y" |> Json.to_string in
    match crv with
    | "P-256" ->
        Util.make_ES256_of_x_y (x, y)
        |> U_Result.map (fun key ->
               let alg = U_Opt.get_with_default ~default:`ES256 alg in
               Es256_pub
                 {
                   alg;
                   kty = `EC;
                   (* Shortcut since that is the only thing we handle *)
                   use =
                     json |> Json.member "use" |> Json.to_string_option
                     |> U_Opt.map use_of_string
                     |> U_Opt.get_with_default ~default:(use_of_alg alg);
                   key;
                   kid = json |> Json.member "kid" |> Json.to_string_option;
                 })
    | "P-521" ->
        Util.make_ES512_of_x_y (x, y)
        |> U_Result.map (fun key ->
               let alg = U_Opt.get_with_default ~default:`ES512 alg in
               Es512_pub
                 {
                   alg;
                   kty = `EC;
                   (* Shortcut since that is the only thing we handle *)
                   use =
                     json |> Json.member "use" |> Json.to_string_option
                     |> U_Opt.map use_of_string
                     |> U_Opt.get_with_default ~default:(use_of_alg alg);
                   key;
                   kid = json |> Json.member "kid" |> Json.to_string_option;
                 })
    | _ -> Error (`Msg "kty and alg doesn't match")
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let priv_ec_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg =
      json |> Json.member "alg" |> Json.to_string_option
      |> U_Opt.map Jwa.alg_of_string
    in
    let crv = json |> Json.member "crv" |> Json.to_string in
    let d =
      json |> Json.member "d" |> Json.to_string |> U_Base64.url_decode
      |> U_Result.map Cstruct.of_string
    in
    match (crv, d) with
    | "P-256", Ok d ->
        let alg = U_Opt.get_with_default ~default:`ES256 alg in
        Mirage_crypto_ec.P256.Dsa.priv_of_cstruct d
        |> U_Result.map_error (fun _ -> `Msg "Could not create key")
        |> U_Result.map (fun key ->
               Es256_priv
                 {
                   alg;
                   kty = `EC;
                   (* Shortcut since that is the only thing we handle *)
                   use =
                     json |> Json.member "use" |> Json.to_string_option
                     |> U_Opt.map use_of_string
                     |> U_Opt.get_with_default ~default:(use_of_alg alg);
                   key;
                   kid = json |> Json.member "kid" |> Json.to_string_option;
                 })
    | "P-521", Ok d ->
        let alg = U_Opt.get_with_default ~default:`ES512 alg in
        Mirage_crypto_ec.P521.Dsa.priv_of_cstruct d
        |> U_Result.map_error (fun _ -> `Msg "Could not create key")
        |> U_Result.map (fun key ->
               Es512_priv
                 {
                   alg;
                   kty = `EC;
                   (* Shortcut since that is the only thing we handle *)
                   use =
                     json |> Json.member "use" |> Json.to_string_option
                     |> U_Opt.map use_of_string
                     |> U_Opt.get_with_default ~default:(use_of_alg alg);
                   key;
                   kid = json |> Json.member "kid" |> Json.to_string_option;
                 })
    | _ -> Error (`Msg "kty and alg doesn't match")
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let of_pub_json (json : Yojson.Safe.t) : (public t, 'error) result =
  let module Json = Yojson.Safe.Util in
  let kty = json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string in
  match kty with
  | `RSA -> pub_rsa_of_json json
  | `oct -> oct_of_json json
  | `EC -> pub_ec_of_json json
  | _ -> Error `Unsupported_kty

let of_pub_json_string str : (public t, 'error) result =
  Yojson.Safe.from_string str |> of_pub_json

let of_priv_json json : (priv t, 'error) result =
  let module Json = Yojson.Safe.Util in
  let kty = json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string in
  match kty with
  | `RSA -> priv_rsa_of_json json
  | `oct -> oct_of_json json
  | `EC -> priv_ec_of_json json
  | _ -> Error `Unsupported_kty

let of_priv_json_string str : (priv t, 'error) result =
  Yojson.Safe.from_string str |> of_priv_json

let pub_of_priv (jwk : priv t) : public t =
  match jwk with
  | Oct oct -> Oct oct
  | Rsa_priv rsa -> Rsa_pub (pub_of_priv_rsa rsa)
  | Es256_priv es -> Es256_pub (pub_of_priv_es256 es)
  | Es512_priv es -> Es512_pub (pub_of_priv_es512 es)

let oct_to_sign_key (oct : oct) : (Cstruct.t, [> `Msg of string ]) result =
  U_Base64.url_decode oct.key |> U_Result.map Cstruct.of_string

let hash_values hash values =
  let module Hash = (val Mirage_crypto.Hash.module_of hash) in
  `Assoc (U_List.filter_map (fun x -> x) values)
  |> Yojson.to_string |> Cstruct.of_string |> Hash.digest |> Cstruct.to_string

let pub_rsa_to_thumbprint hash (pub_rsa : Mirage_crypto_pk.Rsa.pub jwk) =
  let e = Util.get_JWK_component pub_rsa.key.e in
  let n = Util.get_JWK_component pub_rsa.key.n in
  let kty = Jwa.kty_to_string pub_rsa.kty in
  let values =
    [ Some ("e", `String e); Some ("kty", `String kty); Some ("n", `String n) ]
  in
  hash_values hash values

let priv_rsa_to_thumbprint hash (priv_rsa : Mirage_crypto_pk.Rsa.priv jwk) =
  pub_rsa_to_thumbprint hash (pub_of_priv_rsa priv_rsa)

let oct_to_thumbprint _hash (_oct : oct) = Error `Unsafe

let pub_es256_to_thumbprint _hash (pub_es256 : pub_es256) =
  X509.Public_key.id (`P256 pub_es256.key) |> Cstruct.to_string

let priv_es256_to_thumbprint hash (priv_es256 : priv_es256) =
  pub_of_priv_es256 priv_es256 |> pub_es256_to_thumbprint hash

let pub_es512_to_thumbprint _hash (pub_es512 : pub_es512) =
  X509.Public_key.id (`P521 pub_es512.key) |> Cstruct.to_string

let priv_es512_to_thumbprint hash (priv_es512 : priv_es512) =
  pub_of_priv_es512 priv_es512 |> pub_es512_to_thumbprint hash

let get_thumbprint (type a) (hash : Mirage_crypto.Hash.hash) (jwk : a t) =
  match jwk with
  | Rsa_pub rsa -> Ok (pub_rsa_to_thumbprint hash rsa)
  | Rsa_priv rsa -> Ok (priv_rsa_to_thumbprint hash rsa)
  | Es256_pub ec -> Ok (pub_es256_to_thumbprint hash ec)
  | Es256_priv ec -> Ok (priv_es256_to_thumbprint hash ec)
  | Es512_pub ec -> Ok (pub_es512_to_thumbprint hash ec)
  | Es512_priv ec -> Ok (priv_es512_to_thumbprint hash ec)
  | Oct oct -> oct_to_thumbprint hash oct
