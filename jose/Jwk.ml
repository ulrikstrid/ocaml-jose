open Utils

module Util = struct
  let get_JWK_component ?(pad = false) e =
    Z.to_bits e |> RString.rev |> RString.trim_leading_null
    |> RBase64.url_encode ~pad

  let get_component ?(pad = false) e =
    RBase64.url_decode ~pad e
    |> RResult.map (fun x ->
           RString.pad 8 ~c:'\000' x |> RString.rev |> Z.of_bits)

  let kid_of_json json =
    Yojson.Safe.to_string json |> Cstruct.of_string
    |> Mirage_crypto.Hash.SHA256.digest |> Cstruct.to_bytes |> Bytes.to_string
    |> RBase64.url_encode |> RResult.get_exn

  let get_RSA_kid ~e ~n =
    `Assoc [ ("e", `String e); ("kty", `String "RSA"); ("n", `String n) ]
    |> kid_of_json

  let get_OCT_kid k =
    `Assoc [ ("k", `String k); ("kty", `String "oct") ] |> kid_of_json

  let get_JWK_x5t fingerprint =
    fingerprint |> Cstruct.to_bytes |> Bytes.to_string
    |> RBase64.url_encode ~len:20
end

type public = Public

type priv = Private

type 'key jwk = {
  alg : Jwa.alg;
  kty : Jwa.kty;
  use : string option;
  key : 'key;
}

type oct = string jwk

type priv_rsa = Mirage_crypto_pk.Rsa.priv jwk

type pub_rsa = Mirage_crypto_pk.Rsa.pub jwk

type 'a t =
  | Oct : oct -> 'a t
  | Rsa_priv : priv_rsa -> priv t
  | Rsa_pub : pub_rsa -> public t

let get_alg (type a) (t : a t) =
  match t with
  | Rsa_priv rsa -> rsa.alg
  | Rsa_pub rsa -> rsa.alg
  | Oct oct -> oct.alg

let get_kty (type a) (t : a t) =
  match t with Rsa_priv _ -> `RSA | Rsa_pub _ -> `RSA | Oct _ -> `oct

let get_kid (type a) (t : a t) =
  match t with
  | Rsa_priv rsa ->
      RResult.both
        (Util.get_JWK_component rsa.key.e)
        (Util.get_JWK_component rsa.key.n)
      |> RResult.map (fun (e, n) -> Util.get_RSA_kid ~e ~n)
  | Rsa_pub rsa ->
      RResult.both
        (Util.get_JWK_component rsa.key.e)
        (Util.get_JWK_component rsa.key.n)
      |> RResult.map (fun (e, n) -> Util.get_RSA_kid ~e ~n)
  | Oct oct -> Ok (Util.get_OCT_kid oct.key)

let make_oct ?(use : string option) (str : string) : priv t =
  (* Should we make this just return a result intead? *)
  let key = RBase64.url_encode str |> RResult.get_exn in
  Oct { kty = `oct; use; alg = `HS256; key }

let make_priv_rsa ?(use : string option) (rsa_priv : Mirage_crypto_pk.Rsa.priv)
    : priv t =
  Rsa_priv { alg = `RS256; kty = `RSA; use; key = rsa_priv }

let make_pub_rsa ?(use : string option) (rsa_pub : Mirage_crypto_pk.Rsa.pub) :
    public t =
  Rsa_pub { alg = `RS256; kty = `RSA; use; key = rsa_pub }

let of_pub_pem ?(use : string option) pem : (public t, [> `Not_rsa ]) result =
  Cstruct.of_string pem |> X509.Public_key.decode_pem
  |> RResult.flat_map (function
       | `RSA pub_key -> Ok pub_key
       | _ -> Error `Not_rsa)
  |> RResult.map (make_pub_rsa ?use)

let to_pub_pem (type a) (jwk : a t) =
  match jwk with
  | Rsa_pub rsa ->
      Ok (X509.Public_key.encode_pem (`RSA rsa.key) |> Cstruct.to_string)
  | Rsa_priv rsa ->
      rsa.key |> Mirage_crypto_pk.Rsa.pub_of_priv
      |> (fun key -> X509.Public_key.encode_pem (`RSA key))
      |> Cstruct.to_string |> RResult.return
  | _ -> Error `Not_rsa

let of_priv_pem ?(use : string option) pem : (priv t, [> `Not_rsa ]) result =
  Cstruct.of_string pem |> X509.Private_key.decode_pem
  |> RResult.map (function `RSA pub_key -> pub_key)
  |> RResult.map (make_priv_rsa ?use)

let to_priv_pem (jwk : priv t) =
  match jwk with
  | Rsa_priv rsa ->
      Ok (X509.Private_key.encode_pem (`RSA rsa.key) |> Cstruct.to_string)
  | _ -> Error `Not_rsa

let oct_to_json (oct : oct) =
  `Assoc
    [
      ("alg", Jwa.alg_to_json oct.alg);
      ("kty", `String (Jwa.kty_to_string oct.kty));
      ("k", `String oct.key);
      ("kid", `String (Util.get_OCT_kid oct.key));
    ]

let pub_rsa_to_json pub_rsa =
  (* Should I make this a result? It feels like our well-formed key should always be able to become a JSON *)
  let public_key : X509.Public_key.t = `RSA pub_rsa.key in
  let e = Util.get_JWK_component pub_rsa.key.e |> RResult.get_exn in
  let n = Util.get_JWK_component pub_rsa.key.n |> RResult.get_exn in
  let values =
    [
      Some ("alg", Jwa.alg_to_json pub_rsa.alg);
      Some ("e", `String e);
      Some ("n", `String n);
      Some ("kty", `String (Jwa.kty_to_string pub_rsa.kty));
      Some ("kid", `String (Util.get_RSA_kid ~e ~n));
      RJson.to_json_string_opt "use" pub_rsa.use;
      RJson.to_json_string_opt "x5t"
        ( Util.get_JWK_x5t (X509.Public_key.fingerprint ~hash:`SHA1 public_key)
        |> RResult.to_opt );
    ]
  in
  `Assoc (RList.filter_map (fun x -> x) values)

let pub_of_priv_rsa (priv_rsa : priv_rsa) : pub_rsa =
  {
    alg = priv_rsa.alg;
    kty = priv_rsa.kty;
    use = priv_rsa.use;
    key = Mirage_crypto_pk.Rsa.pub_of_priv priv_rsa.key;
  }

let priv_rsa_to_pub_json (priv_rsa : priv_rsa) =
  pub_rsa_to_json (pub_of_priv_rsa priv_rsa)

let priv_rsa_to_priv_json (priv_rsa : priv_rsa) : Yojson.Safe.t =
  (* Should I make this a result? It feels like our well-formed key should always be able to become a JSON *)
  let n = Util.get_JWK_component priv_rsa.key.n in
  let e = Util.get_JWK_component priv_rsa.key.e in
  let d = Util.get_JWK_component priv_rsa.key.d in
  let p = Util.get_JWK_component priv_rsa.key.p in
  let q = Util.get_JWK_component priv_rsa.key.q in
  let dp = Util.get_JWK_component priv_rsa.key.dp in
  let dq = Util.get_JWK_component priv_rsa.key.dq in
  let qi = Util.get_JWK_component priv_rsa.key.q' in
  let n, e, d, p, q, dp, dq, qi =
    RResult.all8 n e d p q dp dq qi |> RResult.get_exn
  in
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
      RJson.to_json_string_opt "use" priv_rsa.use;
      Some ("kid", `String (Util.get_RSA_kid ~e ~n));
    ]
  in
  `Assoc (RList.filter_map (fun x -> x) values)

let to_pub_json (type a) (jwk : a t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_pub_json rsa
  | Rsa_pub rsa -> pub_rsa_to_json rsa

let to_pub_json_string (type a) (jwk : a t) : string =
  to_pub_json jwk |> Yojson.Safe.to_string

let to_priv_json (jwk : priv t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_priv_json rsa

let to_priv_json_string (jwk : priv t) : string =
  to_priv_json jwk |> Yojson.Safe.to_string

let pub_rsa_of_json json : (public t, 'error) result =
  let module Json = Yojson.Safe.Util in
  try
    let e = json |> Json.member "e" |> Json.to_string |> Util.get_component in
    let n = json |> Json.member "n" |> Json.to_string |> Util.get_component in
    RResult.both e n
    |> RResult.flat_map (fun (e, n) -> Mirage_crypto_pk.Rsa.pub ~e ~n)
    |> RResult.map (fun key ->
           Rsa_pub
             {
               alg = `RS256;
               kty = `RSA;
               (* Shortcut since that is the only thing we handle *)
               use = json |> Json.member "use" |> Json.to_string_option;
               key;
             })
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
    RResult.all8 e n d p q dp dq qi
    |> RResult.flat_map (fun (e, n, d, p, q, dp, dq, qi) ->
           Mirage_crypto_pk.Rsa.priv ~e ~n ~d ~p ~q ~dp ~dq ~q':qi)
    |> RResult.map (fun key ->
           Rsa_priv
             {
               alg = `RS256;
               kty = `RSA;
               use = json |> Json.member "use" |> Json.to_string_option;
               key;
             })
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let oct_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    Ok
      (Oct
         {
           alg = `HS256;
           kty = `oct;
           (* Shortcut since that is the only thing we handle *)
           use = json |> Json.member "use" |> Json.to_string_option;
           key = json |> Json.member "k" |> Json.to_string;
         })
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let of_pub_json (json : Yojson.Safe.t) : (public t, 'error) result =
  let module Json = Yojson.Safe.Util in
  let kty = json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string in
  match kty with
  | `RSA -> pub_rsa_of_json json
  | `oct -> oct_of_json json
  | _ -> Error `Unsupported_kty

let of_pub_json_string str : (public t, 'error) result =
  Yojson.Safe.from_string str |> of_pub_json

let of_priv_json json : (priv t, 'error) result =
  let module Json = Yojson.Safe.Util in
  let kty = json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string in
  match kty with
  | `RSA -> priv_rsa_of_json json
  | `oct -> oct_of_json json
  | _ -> Error `Unsupported_kty

let of_priv_json_string str : (priv t, 'error) result =
  Yojson.Safe.from_string str |> of_priv_json

let oct_to_sign_key (oct : oct) : (Cstruct.t, [> `Msg of string ]) result =
  RBase64.url_decode oct.key |> RResult.map Cstruct.of_string
