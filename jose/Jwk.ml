open Utils

module Util = struct
  let trim_leading_null s =
    Astring.String.trim ~drop:(function '\000' -> true | _ -> false) s

  let get_JWK_component ?(pad = false) e =
    Z.to_bits e |> CCString.rev |> trim_leading_null
    |> Base64.encode ~pad ~alphabet:Base64.uri_safe_alphabet

  let get_component ?(pad = false) e =
    Base64.decode ~pad ~alphabet:Base64.uri_safe_alphabet e
    |> RResult.map (fun x ->
           CCString.pad 8 ~c:'\000' x |> CCString.rev |> Z.of_bits)

  let get_JWK_kid id =
    id |> Cstruct.to_string
    |> Base64.encode_exn ~pad:true ~alphabet:Base64.uri_safe_alphabet

  let get_JWK_x5t fingerprint =
    fingerprint |> Hex.of_cstruct |> Hex.to_bytes |> Bytes.to_string
    |> Base64.encode ~pad:false ~alphabet:Base64.uri_safe_alphabet ~len:20
end

module Pub = struct
  (*
  TODO: Implement EC
  {
    "kty":"EC",
    "crv":"P-256",
    "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
  }
  *)

  type oct = {
    kty : Jwa.kty;
    (* `oct *)
    alg : Jwa.alg;
    (* `HS256 *)
    kid : string;
    k : string;
  }

  let oct_of_string str =
    let key = Cstruct.of_string str in
    let k = Cstruct.to_string key |> Base64.encode_exn in
    { kty = `oct; alg = `HS256; kid = str; k }

  type rsa = {
    alg : Jwa.alg;
    (* `RSA *)
    kty : Jwa.kty;
    (* `RS256 *)
    use : string option;
    n : string;
    e : string;
    kid : string;
    x5t : string option;
  }

  type t = RSA of rsa | OCT of oct

  let get_kid t = match t with RSA rsa -> rsa.kid | OCT oct -> oct.kid

  let get_alg t = match t with RSA rsa -> rsa.alg | OCT oct -> oct.alg

  let get_kty t = match t with RSA _ -> `RSA | OCT _ -> `oct

  let rsa_to_pub (rsa : rsa) : (Nocrypto.Rsa.pub, [ `Msg of string ]) result =
    let n = Util.get_component ~pad:true rsa.n in
    let e = Util.get_component rsa.e in
    match (e, n) with
    | Ok e, Ok n -> Ok { e; n }
    | _ -> Error (`Msg "Could not decode JWK")

  let rsa_of_pub (rsa_pub : Nocrypto.Rsa.pub) : (rsa, [ `Msg of string ]) result
      =
    let public_key : X509.Public_key.t = `RSA rsa_pub in
    let n = Util.get_JWK_component ~pad:true rsa_pub.n in
    let e = Util.get_JWK_component rsa_pub.e in
    let kid = Util.get_JWK_kid (X509.Public_key.id public_key) in
    let x5t = Util.get_JWK_x5t (X509.Public_key.fingerprint public_key) in
    match (n, e, x5t) with
    | Ok n, Ok e, Ok x5t ->
        Ok
          {
            alg = `RS256;
            kty = `RSA;
            use = Some "sig";
            n;
            e;
            kid;
            x5t = Some x5t;
          }
    | Ok n, Ok e, _ ->
        Ok { alg = `RS256; kty = `RSA; use = Some "sig"; n; e; kid; x5t = None }
    | Error (`Msg m), _, _ -> Error (`Msg ("n " ^ m))
    | _, Error (`Msg m), _ -> Error (`Msg ("e " ^ m))

  let rsa_of_pub_pem pem : (rsa, [ `Msg of string ]) result =
    Cstruct.of_string pem |> X509.Public_key.decode_pem
    |> RResult.flat_map (function
         | `RSA pub_key -> Ok pub_key
         | _ -> Error (`Msg "Only RSA supported"))
    |> RResult.flat_map rsa_of_pub

  let rsa_to_pub_pem rsa =
    rsa_to_pub rsa
    |> RResult.map (fun p -> X509.Public_key.encode_pem (`RSA p))
    |> RResult.map Cstruct.to_string

  let oct_to_key oct = Cstruct.of_string oct.k

  module Json = Yojson.Safe.Util

  let to_json_from_opt = CCOpt.map_or ~default:`Null Yojson.Safe.from_string

  let rsa_to_json rsa =
    let values =
      [
        Some ("alg", Jwa.alg_to_json rsa.alg);
        Some ("kty", `String (Jwa.kty_to_string rsa.kty));
        RJson.to_json_string_opt "use" rsa.use;
        Some ("n", `String rsa.n);
        Some ("e", `String rsa.e);
        Some ("kid", `String rsa.kid);
        RJson.to_json_string_opt "x5t" rsa.x5t;
      ]
    in
    `Assoc (CCList.filter_map (fun x -> x) values)

  let oct_to_json (oct : oct) =
    `Assoc
      [
        ("alg", Jwa.alg_to_json oct.alg);
        ("kty", `String (Jwa.kty_to_string oct.kty));
        ("k", `String oct.k);
        ("kid", `String oct.kid);
      ]

  let to_json t =
    match t with RSA rsa -> rsa_to_json rsa | OCT oct -> oct_to_json oct

  let rsa_of_json json =
    try
      Ok
        (RSA
           {
             alg = json |> Json.member "alg" |> Jwa.alg_of_json;
             kty =
               json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string;
             use = json |> Json.member "use" |> Json.to_string_option;
             n = json |> Json.member "n" |> Json.to_string;
             e = json |> Json.member "e" |> Json.to_string;
             kid = json |> Json.member "kid" |> Json.to_string;
             x5t = json |> Json.member "x5t" |> Json.to_string_option;
           })
    with Json.Type_error (s, _) -> Error (`Msg s)

  let oct_of_json json =
    try
      Ok
        (OCT
           {
             alg = json |> Json.member "alg" |> Jwa.alg_of_json;
             kty =
               json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string;
             k = json |> Json.member "k" |> Json.to_string;
             kid = json |> Json.member "kid" |> Json.to_string;
           })
    with Json.Type_error (s, _) -> Error (`Msg s)

  let of_json json =
    let kty =
      json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string
    in
    match kty with
    | `RSA -> rsa_of_json json
    | `oct -> oct_of_json json
    | _ -> Error (`Msg "kty not supported")

  let of_string str = Yojson.Safe.from_string str |> of_json

  let to_string t = to_json t |> Yojson.Safe.to_string
end

module Priv = struct
  type t = {
    alg : Jwa.alg;
    kty : Jwa.kty;
    n : string;
    e : string;
    d : string;
    p : string;
    q : string;
    dp : string;
    dq : string;
    qi : string;
    kid : string;
  }

  let of_priv (rsa_priv : Nocrypto.Rsa.priv) =
    let n = Util.get_JWK_component ~pad:true rsa_priv.n in
    let e = Util.get_JWK_component rsa_priv.e in
    let d = Util.get_JWK_component rsa_priv.d in
    let p = Util.get_JWK_component rsa_priv.p in
    let q = Util.get_JWK_component rsa_priv.q in
    let dp = Util.get_JWK_component rsa_priv.dp in
    let dq = Util.get_JWK_component rsa_priv.dq in
    let qi = Util.get_JWK_component rsa_priv.q' in

    match (n, e, d, p, q, dp, dq, qi) with
    | Ok n, Ok e, Ok d, Ok p, Ok q, Ok dp, Ok dq, Ok qi ->
        Ok
          {
            alg = `RS256;
            kty = `RSA;
            n;
            e;
            d;
            p;
            q;
            dp;
            dq;
            qi;
            kid = "unknown";
          }
    | _ -> Error (`Msg "Something failed")

  let to_priv (t : t) : (Nocrypto.Rsa.priv, [ `Msg of string ]) result =
    let n = Util.get_component ~pad:true t.n in
    let e = Util.get_component t.e in
    let d = Util.get_component t.d in
    let p = Util.get_component t.p in
    let q = Util.get_component t.q in
    let dp = Util.get_component t.dp in
    let dq = Util.get_component t.dq in
    let qi = Util.get_component t.qi in
    match (n, e, d, p, q, dp, dq, qi) with
    | Ok n, Ok e, Ok d, Ok p, Ok q, Ok dp, Ok dq, Ok qi ->
        Ok { e; n; d; p; q; dp; dq; q' = qi }
    | _ -> Error (`Msg "Could not decode JWK")

  let of_priv_pem pem =
    Cstruct.of_string pem |> X509.Private_key.decode_pem
    |> RResult.flat_map (function `RSA pub_key -> Ok pub_key)
    |> RResult.flat_map of_priv

  let to_priv_pem t =
    to_priv t
    |> RResult.map (fun p -> X509.Private_key.encode_pem (`RSA p))
    |> RResult.map Cstruct.to_string

  module Json = Yojson.Safe.Util

  let to_json t =
    `Assoc
      [
        ("alg", Jwa.alg_to_json t.alg);
        ("kty", `String (t.kty |> Jwa.kty_to_string));
        ("n", `String t.n);
        ("e", `String t.e);
        ("d", `String t.n);
        ("p", `String t.e);
        ("q", `String t.n);
        ("dp", `String t.e);
        ("dq", `String t.n);
        ("qi", `String t.e);
        ("kid", `String t.kid);
      ]

  let of_json json =
    try
      Ok
        {
          alg = json |> Json.member "alg" |> Jwa.alg_of_json;
          kty = json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string;
          n = json |> Json.member "n" |> Json.to_string;
          e = json |> Json.member "e" |> Json.to_string;
          d = json |> Json.member "d" |> Json.to_string;
          p = json |> Json.member "p" |> Json.to_string;
          q = json |> Json.member "q" |> Json.to_string;
          dp = json |> Json.member "dp" |> Json.to_string;
          dq = json |> Json.member "dq" |> Json.to_string;
          qi = json |> Json.member "qi" |> Json.to_string;
          kid = json |> Json.member "kid" |> Json.to_string;
        }
    with Json.Type_error (s, _) -> Error (`Msg s)

  let of_string str = Yojson.Safe.from_string str |> of_json

  let to_string t = to_json t |> Yojson.Safe.to_string
end
