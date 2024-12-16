open Utils

module Util = struct
  let get_JWK_component ?(pad = false) e : string =
    Z.to_bits e |> U_String.rev |> U_String.trim_leading_null
    |> U_Base64.url_encode_string ~pad

  let get_component ?(pad = false) e =
    U_Base64.url_decode ~pad e
    |> Result.map (fun x ->
           U_String.pad ~len:8 ~c:'\000' x |> U_String.rev |> Z.of_bits)

  let kid_of_json json =
    Yojson.Safe.to_string json |> Digestif.SHA256.digest_string
    |> Digestif.SHA256.to_raw_string |> U_Base64.url_encode_string

  let get_JWK_x5t fingerprint = U_Base64.url_encode ~len:20 fingerprint

  let get_ESXXX_x_y ~split_at ~pub_to_string key =
    let point = pub_to_string key in
    let x_cs, y_cs =
      U_String.split (String.sub point 1 (String.length point - 1)) split_at
    in
    let x = x_cs |> U_Base64.url_encode_string in
    let y = y_cs |> U_Base64.url_encode_string in
    (x, y)

  let make_ESXXX_of_x_y ~pub_of_string (x, y) =
    let x = U_Base64.url_decode x in
    let y = U_Base64.url_decode y in
    match (x, y) with
    | Ok x, Ok y ->
        let four =
          let cs = Bytes.create 1 in
          Bytes.set_uint8 cs 0 4;
          Bytes.unsafe_to_string cs
        in
        let point = String.concat "" [ four; x; y ] in
        pub_of_string point |> Result.get_ok |> Result.ok
    | Error e, _ | _, Error e -> Error e

  let get_ES256_x_y =
    get_ESXXX_x_y ~split_at:32 (* 64 octets split in 2 *)
      ~pub_to_string:Mirage_crypto_ec.P256.Dsa.pub_to_octets

  let make_ES256_of_x_y =
    make_ESXXX_of_x_y ~pub_of_string:Mirage_crypto_ec.P256.Dsa.pub_of_octets

  let get_ES384_x_y =
    get_ESXXX_x_y ~split_at:48 (* 96 octets split in 2 *)
      ~pub_to_string:Mirage_crypto_ec.P384.Dsa.pub_to_octets

  let make_ES384_of_x_y =
    make_ESXXX_of_x_y ~pub_of_string:Mirage_crypto_ec.P384.Dsa.pub_of_octets

  let get_ES512_x_y =
    get_ESXXX_x_y ~split_at:66 (* 132 octets split in 2 *)
      ~pub_to_string:Mirage_crypto_ec.P521.Dsa.pub_to_octets

  let make_ES512_of_x_y =
    make_ESXXX_of_x_y ~pub_of_string:Mirage_crypto_ec.P521.Dsa.pub_of_octets
end

type use = [ `Sig | `Enc | `Unsupported of string ]

let use_to_string use =
  match use with `Sig -> "sig" | `Enc -> "enc" | `Unsupported str -> str

let use_of_string use =
  match use with "sig" -> `Sig | "enc" -> `Enc | str -> `Unsupported str

let alg_of_use_and_kty ?(use : use = `Sig) (kty : Jwa.kty) : Jwa.alg =
  match (use, kty) with
  | `Sig, `oct -> `HS256
  | `Sig, `RSA -> `RS256
  | `Sig, `EC -> `ES512
  | `Sig, `OKP -> `EdDSA
  | `Enc, `RSA -> `RSA_OAEP
  | `Enc, `oct -> `Unsupported "encryption with oct is not supported yet"
  | `Enc, `EC ->
      `Unsupported "encryption with eliptic curves are not supported yet"
  | `Enc, `OKP ->
      `Unsupported "encryption with octet key paris are not supported yet"
  | `Unsupported u, _ -> `Unsupported ("We don't know what to do with use: " ^ u)
  | _, `Unsupported k -> `Unsupported ("We don't know what to do with kty: " ^ k)

let use_of_alg (alg : Jwa.alg) =
  match alg with
  | `HS256 -> `Sig
  | `RS256 -> `Sig
  | `ES256 -> `Sig
  | `ES384 -> `Sig
  | `ES512 -> `Sig
  | `EdDSA -> `Sig
  | `RSA_OAEP -> `Enc
  | `RSA1_5 -> `Enc
  | `None -> `Unsupported "none"
  | `Unsupported str -> `Unsupported str

type public = Public
type priv = Private

type 'key jwk = {
  alg : Jwa.alg option;
  kty : Jwa.kty;
  use : use option;
  kid : string option;
  key : 'key;
}

type oct = string jwk
type priv_rsa = Mirage_crypto_pk.Rsa.priv jwk
type pub_rsa = Mirage_crypto_pk.Rsa.pub jwk
type priv_es256 = Mirage_crypto_ec.P256.Dsa.priv jwk
type pub_es256 = Mirage_crypto_ec.P256.Dsa.pub jwk
type priv_es384 = Mirage_crypto_ec.P384.Dsa.priv jwk
type pub_es384 = Mirage_crypto_ec.P384.Dsa.pub jwk
type priv_es512 = Mirage_crypto_ec.P521.Dsa.priv jwk
type pub_es512 = Mirage_crypto_ec.P521.Dsa.pub jwk
type priv_ed25519 = Mirage_crypto_ec.Ed25519.priv jwk
type pub_ed25519 = Mirage_crypto_ec.Ed25519.pub jwk

type 'a t =
  | Oct : oct -> 'a t
  | Rsa_priv : priv_rsa -> priv t
  | Rsa_pub : pub_rsa -> public t
  | Es256_priv : priv_es256 -> priv t
  | Es256_pub : pub_es256 -> public t
  | Es384_priv : priv_es384 -> priv t
  | Es384_pub : pub_es384 -> public t
  | Es512_priv : priv_es512 -> priv t
  | Es512_pub : pub_es512 -> public t
  | Ed25519_priv : priv_ed25519 -> priv t
  | Ed25519_pub : pub_ed25519 -> public t

let get_alg (type a) (t : a t) : Jwa.alg option =
  match t with
  | Rsa_priv rsa -> rsa.alg
  | Rsa_pub rsa -> rsa.alg
  | Es256_priv es -> es.alg
  | Es256_pub es -> es.alg
  | Es384_priv es -> es.alg
  | Es384_pub es -> es.alg
  | Es512_priv es -> es.alg
  | Es512_pub es -> es.alg
  | Ed25519_priv es -> es.alg
  | Ed25519_pub es -> es.alg
  | Oct oct -> oct.alg

let get_kty (type a) (t : a t) =
  match t with
  | Rsa_priv _ -> `RSA
  | Rsa_pub _ -> `RSA
  | Es256_priv _ -> `EC
  | Es256_pub _ -> `EC
  | Es384_priv _ -> `EC
  | Es384_pub _ -> `EC
  | Es512_priv _ -> `EC
  | Es512_pub _ -> `EC
  | Ed25519_priv _ -> `OKP
  | Ed25519_pub _ -> `OKP
  | Oct _ -> `oct

let get_kid (type a) (t : a t) =
  match t with
  | Rsa_priv rsa -> rsa.kid
  | Rsa_pub rsa -> rsa.kid
  | Es256_priv es -> es.kid
  | Es256_pub es -> es.kid
  | Es384_priv es -> es.kid
  | Es384_pub es -> es.kid
  | Es512_priv es -> es.kid
  | Es512_pub es -> es.kid
  | Ed25519_priv es -> es.kid
  | Ed25519_pub es -> es.kid
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
    | Es384_priv es ->
        let x, y =
          Util.get_ES384_x_y (Mirage_crypto_ec.P384.Dsa.pub_of_priv es.key)
        in
        `Assoc
          [
            ("crv", `String "P-384");
            ("kty", `String "EC");
            ("x", `String x);
            ("y", `String y);
          ]
        |> Util.kid_of_json
    | Es384_pub es ->
        let x, y = Util.get_ES384_x_y es.key in
        `Assoc
          [
            ("crv", `String "P-384");
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
    | Ed25519_priv okt ->
        let x =
          Mirage_crypto_ec.Ed25519.pub_of_priv okt.key
          |> Mirage_crypto_ec.Ed25519.pub_to_octets
          |> U_Base64.url_encode_string
        in
        `Assoc
          [
            ("crv", `String "Ed25519"); ("kty", `String "OKP"); ("x", `String x);
          ]
        |> Util.kid_of_json
    | Ed25519_pub okt ->
        let x =
          Mirage_crypto_ec.Ed25519.pub_to_octets okt.key
          |> U_Base64.url_encode_string
        in
        `Assoc
          [
            ("crv", `String "Ed25519"); ("kty", `String "OKP"); ("x", `String x);
          ]
        |> Util.kid_of_json
    | Oct oct ->
        `Assoc [ ("k", `String oct.key); ("kty", `String "oct") ]
        |> Util.kid_of_json
  in
  Some kid

let make_oct ?use (str : string) : 'a t =
  (* Should we make this just return a result intead? *)
  let key = U_Base64.url_encode_string str in
  let jwk = { kty = `oct; use; alg = Some `HS256; key; kid = None } in
  Oct { jwk with kid = make_kid (Oct jwk) }

let make_priv_rsa ?use (rsa_priv : Mirage_crypto_pk.Rsa.priv) : priv t =
  let kty : Jwa.kty = `RSA in
  let alg : Jwa.alg option =
    Option.map (fun use -> alg_of_use_and_kty ~use kty) use
  in
  let jwk = { alg; kty; use; key = rsa_priv; kid = None } in
  Rsa_priv { jwk with kid = make_kid (Rsa_priv jwk) }

let make_priv_es256 ?use (es256_priv : Mirage_crypto_ec.P256.Dsa.priv) : priv t
    =
  let kty : Jwa.kty = `EC in
  let alg = Some `ES256 in
  let jwk = { alg; kty; use; key = es256_priv; kid = None } in
  Es256_priv { jwk with kid = make_kid (Es256_priv jwk) }

let make_priv_es384 ?use (es384_priv : Mirage_crypto_ec.P384.Dsa.priv) : priv t
    =
  let kty : Jwa.kty = `EC in
  let alg = Some `ES384 in
  let jwk = { alg; kty; use; key = es384_priv; kid = None } in
  Es384_priv { jwk with kid = make_kid (Es384_priv jwk) }

let make_priv_es512 ?use (es512_priv : Mirage_crypto_ec.P521.Dsa.priv) : priv t
    =
  let kty : Jwa.kty = `EC in
  let alg = Some `ES512 in
  let jwk = { alg; kty; use; key = es512_priv; kid = None } in
  Es512_priv { jwk with kid = make_kid (Es512_priv jwk) }

let make_pub_rsa ?use (rsa_pub : Mirage_crypto_pk.Rsa.pub) : public t =
  let kty : Jwa.kty = `RSA in
  let alg = Option.map (fun use -> alg_of_use_and_kty ~use kty) use in
  let jwk = { alg; kty; use; key = rsa_pub; kid = None } in
  Rsa_pub { jwk with kid = make_kid (Rsa_pub jwk) }

let make_pub_es256 ?use (es256_pub : Mirage_crypto_ec.P256.Dsa.pub) : public t =
  let kty : Jwa.kty = `EC in
  let alg = Some `ES256 in
  let jwk = { alg; kty; use; key = es256_pub; kid = None } in
  Es256_pub { jwk with kid = make_kid (Es256_pub jwk) }

let make_pub_es384 ?use (es384_pub : Mirage_crypto_ec.P384.Dsa.pub) : public t =
  let kty : Jwa.kty = `EC in
  let alg = Some `ES384 in
  let jwk = { alg; kty; use; key = es384_pub; kid = None } in
  Es384_pub { jwk with kid = make_kid (Es384_pub jwk) }

let make_pub_es512 ?use (es512_pub : Mirage_crypto_ec.P521.Dsa.pub) : public t =
  let kty : Jwa.kty = `EC in
  let alg = Some `ES512 in
  let jwk = { alg; kty; use; key = es512_pub; kid = None } in
  Es512_pub { jwk with kid = make_kid (Es512_pub jwk) }

let of_priv_x509 ?use x509 : (priv t, [> `Unsupported_kty ]) result =
  match x509 with
  | `RSA priv_key -> Ok (make_priv_rsa ?use priv_key)
  | `P256 priv_key -> Ok (make_priv_es256 ?use priv_key)
  | `P384 priv_key -> Ok (make_priv_es384 ?use priv_key)
  | `P521 priv_key -> Ok (make_priv_es512 ?use priv_key)
  | _ -> Error `Unsupported_kty

let of_pub_x509 ?use (x509 : X509.Public_key.t) :
    (public t, [> `Unsupported_kty ]) result =
  match x509 with
  | `RSA public_key -> Ok (make_pub_rsa ?use public_key)
  | `P256 public_key -> Ok (make_pub_es256 ?use public_key)
  | `P384 public_key -> Ok (make_pub_es384 ?use public_key)
  | `P521 public_key -> Ok (make_pub_es512 ?use public_key)
  | _ -> Error `Unsupported_kty

let of_pub_pem ?use pem : (public t, [> `Unsupported_kty ]) result =
  Result.bind (X509.Public_key.decode_pem pem) (of_pub_x509 ?use)

let to_pub_pem (type a) (jwk : a t) =
  match jwk with
  | Rsa_pub rsa -> Ok (X509.Public_key.encode_pem (`RSA rsa.key))
  | Rsa_priv rsa ->
      rsa.key |> Mirage_crypto_pk.Rsa.pub_of_priv
      |> (fun key -> X509.Public_key.encode_pem (`RSA key))
      |> Result.ok
  | Es256_pub ec -> Ok (X509.Public_key.encode_pem (`P256 ec.key))
  | Es256_priv ec ->
      ec.key |> Mirage_crypto_ec.P256.Dsa.pub_of_priv
      |> (fun key -> X509.Public_key.encode_pem (`P256 key))
      |> Result.ok
  | Es384_pub ec -> Ok (X509.Public_key.encode_pem (`P384 ec.key))
  | Es384_priv ec ->
      ec.key |> Mirage_crypto_ec.P384.Dsa.pub_of_priv
      |> (fun key -> X509.Public_key.encode_pem (`P384 key))
      |> Result.ok
  | Es512_pub ec -> Ok (X509.Public_key.encode_pem (`P521 ec.key))
  | Es512_priv ec ->
      ec.key |> Mirage_crypto_ec.P521.Dsa.pub_of_priv
      |> (fun key -> X509.Public_key.encode_pem (`P521 key))
      |> Result.ok
  | _ -> Error `Unsupported_kty

let of_priv_pem ?use pem : (priv t, [> `Unsupported_kty ]) result =
  let pem = X509.Private_key.decode_pem pem in
  Result.bind pem (of_priv_x509 ?use)

let to_priv_pem (jwk : priv t) =
  match jwk with
  | Rsa_priv rsa -> Ok (X509.Private_key.encode_pem (`RSA rsa.key))
  | Es256_priv ec -> Ok (X509.Private_key.encode_pem (`P256 ec.key))
  | Es384_priv ec -> Ok (X509.Private_key.encode_pem (`P384 ec.key))
  | Es512_priv ec -> Ok (X509.Private_key.encode_pem (`P521 ec.key))
  | _ -> Error `Unsupported_kty

let oct_to_json (oct : oct) =
  let values =
    [
      Option.map (fun alg -> ("alg", Jwa.alg_to_json alg)) oct.alg;
      Some ("kty", `String (Jwa.kty_to_string oct.kty));
      Some ("k", `String oct.key);
      RJson.to_json_string_opt "kid" oct.kid;
    ]
  in
  `Assoc (List.filter_map Fun.id values)

let pub_rsa_to_json pub_rsa =
  (* Should I make this a result? It feels like our well-formed key should
     always be able to become a JSON *)
  let public_key : X509.Public_key.t = `RSA pub_rsa.key in
  let e = Util.get_JWK_component pub_rsa.key.e in
  let n = Util.get_JWK_component pub_rsa.key.n in
  let values =
    [
      Option.map (fun alg -> ("alg", Jwa.alg_to_json alg)) pub_rsa.alg;
      Some ("e", `String e);
      Some ("n", `String n);
      Some ("kty", `String (Jwa.kty_to_string pub_rsa.kty));
      RJson.to_json_string_opt "kid" pub_rsa.kid;
      Option.map (fun use -> ("use", `String (use_to_string use))) pub_rsa.use;
      RJson.to_json_string_opt "x5t"
        (Util.get_JWK_x5t (X509.Public_key.fingerprint ~hash:`SHA1 public_key)
        |> Result.to_option);
    ]
  in
  `Assoc (List.filter_map Fun.id values)

let pub_of_priv_rsa (priv_rsa : priv_rsa) : pub_rsa =
  { priv_rsa with key = Mirage_crypto_pk.Rsa.pub_of_priv priv_rsa.key }

let pub_of_priv_es256 (priv_es256 : priv_es256) : pub_es256 =
  { priv_es256 with key = Mirage_crypto_ec.P256.Dsa.pub_of_priv priv_es256.key }

let pub_of_priv_es384 (priv_es384 : priv_es384) : pub_es384 =
  { priv_es384 with key = Mirage_crypto_ec.P384.Dsa.pub_of_priv priv_es384.key }

let pub_of_priv_es512 (priv_es512 : priv_es512) : pub_es512 =
  { priv_es512 with key = Mirage_crypto_ec.P521.Dsa.pub_of_priv priv_es512.key }

let pub_of_priv_ed25519 (priv_ed25519 : priv_ed25519) : pub_ed25519 =
  {
    priv_ed25519 with
    key = Mirage_crypto_ec.Ed25519.pub_of_priv priv_ed25519.key;
  }

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
      Option.map (fun alg -> ("alg", Jwa.alg_to_json alg)) priv_rsa.alg;
      Some ("e", `String e);
      Some ("n", `String n);
      Some ("d", `String d);
      Some ("p", `String p);
      Some ("q", `String q);
      Some ("dp", `String dp);
      Some ("dq", `String dq);
      Some ("qi", `String qi);
      Some ("kty", `String (priv_rsa.kty |> Jwa.kty_to_string));
      Option.map (fun use -> ("use", `String (use_to_string use))) priv_rsa.use;
      RJson.to_json_string_opt "kid" priv_rsa.kid;
    ]
  in
  `Assoc (List.filter_map Fun.id values)

let pub_esXXX_to_pub_json ~get_ESXXX_x_y ~crv (pub : 'a) : Yojson.Safe.t =
  let x, y = get_ESXXX_x_y pub.key in
  let values =
    [
      Option.map (fun alg -> ("alg", Jwa.alg_to_json alg)) pub.alg;
      Some ("crv", `String crv);
      Some ("x", `String x);
      Some ("y", `String y);
      Some ("kty", `String (pub.kty |> Jwa.kty_to_string));
      Option.map (fun use -> ("use", `String (use_to_string use))) pub.use;
      RJson.to_json_string_opt "kid" pub.kid;
    ]
  in
  `Assoc (List.filter_map Fun.id values)

let priv_esXXX_to_priv_json ~get_ESXXX_x_y ~pub_of_priv ~priv_to_string ~crv
    (priv : 'a) : Yojson.Safe.t =
  let x, y = get_ESXXX_x_y (pub_of_priv priv.key) in
  let d = priv_to_string priv.key |> U_Base64.url_encode_string in
  let values =
    [
      Option.map (fun alg -> ("alg", Jwa.alg_to_json alg)) priv.alg;
      Some ("crv", `String crv);
      Some ("x", `String x);
      Some ("y", `String y);
      Some ("d", `String d);
      Some ("kty", `String (priv.kty |> Jwa.kty_to_string));
      Option.map (fun use -> ("use", `String (use_to_string use))) priv.use;
      RJson.to_json_string_opt "kid" priv.kid;
    ]
  in
  `Assoc (List.filter_map Fun.id values)

let pub_es256_to_pub_json =
  pub_esXXX_to_pub_json ~get_ESXXX_x_y:Util.get_ES256_x_y ~crv:"P-256"

let priv_es256_to_pub_json (priv_es256 : priv_es256) : Yojson.Safe.t =
  pub_of_priv_es256 priv_es256 |> pub_es256_to_pub_json

let priv_es256_to_priv_json =
  priv_esXXX_to_priv_json ~get_ESXXX_x_y:Util.get_ES256_x_y
    ~pub_of_priv:Mirage_crypto_ec.P256.Dsa.pub_of_priv
    ~priv_to_string:Mirage_crypto_ec.P256.Dsa.priv_to_octets ~crv:"P-256"

let pub_es384_to_pub_json (pub_es384 : pub_es384) : Yojson.Safe.t =
  pub_esXXX_to_pub_json ~get_ESXXX_x_y:Util.get_ES384_x_y ~crv:"P-384" pub_es384

let priv_es384_to_pub_json (priv_es384 : priv_es384) : Yojson.Safe.t =
  pub_of_priv_es384 priv_es384 |> pub_es384_to_pub_json

let priv_es384_to_priv_json =
  priv_esXXX_to_priv_json ~get_ESXXX_x_y:Util.get_ES384_x_y
    ~pub_of_priv:Mirage_crypto_ec.P384.Dsa.pub_of_priv
    ~priv_to_string:Mirage_crypto_ec.P384.Dsa.priv_to_octets ~crv:"P-384"

let pub_es512_to_pub_json (pub_es512 : pub_es512) : Yojson.Safe.t =
  pub_esXXX_to_pub_json ~get_ESXXX_x_y:Util.get_ES512_x_y ~crv:"P-521" pub_es512

let priv_es512_to_pub_json (priv_es512 : priv_es512) : Yojson.Safe.t =
  pub_of_priv_es512 priv_es512 |> pub_es512_to_pub_json

let priv_es512_to_priv_json =
  priv_esXXX_to_priv_json ~get_ESXXX_x_y:Util.get_ES512_x_y
    ~pub_of_priv:Mirage_crypto_ec.P521.Dsa.pub_of_priv
    ~priv_to_string:Mirage_crypto_ec.P521.Dsa.priv_to_octets ~crv:"P-521"

let pub_ed25519_to_pub_json okp =
  `Assoc
    [
      ("kty", `String "OKP");
      ("crv", `String "Ed25519");
      ( "x",
        `String
          (okp.key |> Mirage_crypto_ec.Ed25519.pub_to_octets
         |> U_Base64.url_encode_string) );
    ]

let priv_ed25519_to_pub_json okp =
  pub_of_priv_ed25519 okp |> pub_ed25519_to_pub_json

let priv_ed25519_to_priv_json okp =
  let pub_key = Mirage_crypto_ec.Ed25519.pub_of_priv okp.key in
  `Assoc
    [
      ("kty", `String "OKP");
      ("crv", `String "Ed25519");
      ( "d",
        `String
          (okp.key |> Mirage_crypto_ec.Ed25519.priv_to_octets
         |> U_Base64.url_encode_string) );
      ( "x",
        `String
          (pub_key |> Mirage_crypto_ec.Ed25519.pub_to_octets
         |> U_Base64.url_encode_string) );
    ]

let to_pub_json (type a) (jwk : a t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_pub_json rsa
  | Rsa_pub rsa -> pub_rsa_to_json rsa
  | Es256_priv ec -> priv_es256_to_pub_json ec
  | Es256_pub ec -> pub_es256_to_pub_json ec
  | Es384_priv ec -> priv_es384_to_pub_json ec
  | Es384_pub ec -> pub_es384_to_pub_json ec
  | Es512_priv ec -> priv_es512_to_pub_json ec
  | Es512_pub ec -> pub_es512_to_pub_json ec
  | Ed25519_priv okp -> priv_ed25519_to_pub_json okp
  | Ed25519_pub okp -> pub_ed25519_to_pub_json okp

let to_pub_json_string (type a) (jwk : a t) : string =
  to_pub_json jwk |> Yojson.Safe.to_string

let to_priv_json (jwk : priv t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_priv_json rsa
  | Es256_priv ec -> priv_es256_to_priv_json ec
  | Es384_priv ec -> priv_es384_to_priv_json ec
  | Es512_priv ec -> priv_es512_to_priv_json ec
  | Ed25519_priv okp -> priv_ed25519_to_priv_json okp

let to_priv_json_string (jwk : priv t) : string =
  to_priv_json jwk |> Yojson.Safe.to_string

let pub_rsa_of_json json : (public t, 'error) result =
  let module Json = Yojson.Safe.Util in
  try
    let e = json |> Json.member "e" |> Json.to_string |> Util.get_component in
    let n = json |> Json.member "n" |> Json.to_string |> Util.get_component in
    match (e, n) with
    | Error e, _ | _, Error e -> Error e
    | Ok e, Ok n ->
        let pub = Mirage_crypto_pk.Rsa.pub ~e ~n in
        Result.bind pub (fun key ->
            let alg =
              json |> Json.member "alg" |> Json.to_string_option
              |> Option.map Jwa.alg_of_string
            in
            let use =
              json |> Json.member "use" |> Json.to_string_option
              |> Option.map use_of_string
            in
            let kid = json |> Json.member "kid" |> Json.to_string_option in
            let kty = `RSA in
            match (alg, use) with
            | Some _, Some _ -> Ok (Rsa_pub { alg; kty; use; key; kid })
            | Some alg, None ->
                Ok
                  (Rsa_pub
                     {
                       alg = Some alg;
                       kty;
                       use = Some (use_of_alg alg);
                       key;
                       kid;
                     })
            | None, Some use ->
                Ok
                  (Rsa_pub
                     {
                       alg = Some (alg_of_use_and_kty ~use kty);
                       kty;
                       use = Some use;
                       key;
                       kid;
                     })
            | alg, use -> Ok (Rsa_pub { alg; kty; use; key; kid }))
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
    let all8 = U_Result.all8 e n d p q dp dq qi in
    let priv =
      Result.bind all8 (fun (e, n, d, p, q, dp, dq, qi) ->
          Mirage_crypto_pk.Rsa.priv ~e ~n ~d ~p ~q ~dp ~dq ~q':qi)
    in
    Result.bind priv (fun key ->
        let alg =
          json |> Json.member "alg" |> Json.to_string_option
          |> Option.map Jwa.alg_of_string
        in
        let use =
          json |> Json.member "use" |> Json.to_string_option
          |> Option.map use_of_string
        in
        let kid = json |> Json.member "kid" |> Json.to_string_option in
        let kty = `RSA in
        match (alg, use) with
        | Some _, Some _ -> Ok (Rsa_priv { alg; kty; use; key; kid })
        | Some alg, None ->
            Ok
              (Rsa_priv
                 { alg = Some alg; kty; use = Some (use_of_alg alg); key; kid })
        | None, Some use ->
            Ok
              (Rsa_priv
                 {
                   alg = Some (alg_of_use_and_kty ~use kty);
                   kty;
                   use = Some use;
                   key;
                   kid;
                 })
        | None, None -> Ok (Rsa_priv { alg; kty; use; key; kid }))
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let oct_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg =
      json |> Json.member "alg" |> Json.to_string_option
      |> Option.map Jwa.alg_of_string
    in
    Ok
      (Oct
         {
           alg;
           kty = `oct;
           (* Shortcut since that is the only thing we handle *)
           use =
             json |> Json.member "use" |> Json.to_string_option
             |> Option.map use_of_string;
           key = json |> Json.member "k" |> Json.to_string;
           kid = json |> Json.member "kid" |> Json.to_string_option;
         })
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let pub_ec_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg =
      json |> Json.member "alg" |> Json.to_string_option
      |> Option.map Jwa.alg_of_string
    in
    let crv = json |> Json.member "crv" |> Json.to_string in
    let x = json |> Json.member "x" |> Json.to_string in
    let y = json |> Json.member "y" |> Json.to_string in
    let make_jwk key =
      {
        alg;
        kty = `EC;
        (* Shortcut since that is the only thing we handle *)
        use =
          json |> Json.member "use" |> Json.to_string_option
          |> Option.map use_of_string;
        key;
        kid = json |> Json.member "kid" |> Json.to_string_option;
      }
    in
    match crv with
    | "P-256" ->
        Util.make_ES256_of_x_y (x, y)
        |> Result.map (fun key -> Es256_pub (make_jwk key))
    | "P-384" ->
        Util.make_ES384_of_x_y (x, y)
        |> Result.map (fun key -> Es384_pub (make_jwk key))
    | "P-521" ->
        Util.make_ES512_of_x_y (x, y)
        |> Result.map (fun key -> Es512_pub (make_jwk key))
    | _ -> Error (`Msg "kty and alg doesn't match")
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let priv_ec_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg =
      json |> Json.member "alg" |> Json.to_string_option
      |> Option.map Jwa.alg_of_string
    in
    let crv = json |> Json.member "crv" |> Json.to_string in
    let d = json |> Json.member "d" |> Json.to_string |> U_Base64.url_decode in
    let make_jwk key =
      {
        alg;
        kty = `EC;
        (* Shortcut since that is the only thing we handle *)
        use =
          json |> Json.member "use" |> Json.to_string_option
          |> Option.map use_of_string;
        key;
        kid = json |> Json.member "kid" |> Json.to_string_option;
      }
    in
    match (crv, d) with
    | "P-256", Ok d ->
        Mirage_crypto_ec.P256.Dsa.priv_of_octets d
        |> Result.map_error (fun _ -> `Msg "Could not create key")
        |> Result.map (fun key -> Es256_priv (make_jwk key))
    | "P-384", Ok d ->
        Mirage_crypto_ec.P384.Dsa.priv_of_octets d
        |> Result.map_error (fun _ -> `Msg "Could not create key")
        |> Result.map (fun key -> Es384_priv (make_jwk key))
    | "P-521", Ok d ->
        Mirage_crypto_ec.P521.Dsa.priv_of_octets d
        |> Result.map_error (fun _ -> `Msg "Could not create key")
        |> Result.map (fun key -> Es512_priv (make_jwk key))
    | _ -> Error (`Msg "kty and alg doesn't match")
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let pub_okp_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg =
      json |> Json.member "alg" |> Json.to_string_option
      |> Option.map Jwa.alg_of_string
    in
    (* TODO: This is needed if we want more curves *)
    let _crv = json |> Json.member "crv" |> Json.to_string in
    let x = json |> Json.member "x" |> Json.to_string |> U_Base64.url_decode in
    let make_jwk key =
      {
        alg;
        kty = `OKP;
        (* Shortcut since that is the only thing we handle *)
        use =
          json |> Json.member "use" |> Json.to_string_option
          |> Option.map use_of_string;
        key;
        kid = json |> Json.member "kid" |> Json.to_string_option;
      }
    in
    Result.bind x (fun str ->
        Mirage_crypto_ec.Ed25519.pub_of_octets str
        |> Result.map_error (fun _ -> `Msg "Could not create key"))
    |> Result.map (fun key -> Ed25519_pub (make_jwk key))
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let priv_okp_of_json json =
  let module Json = Yojson.Safe.Util in
  try
    let alg =
      json |> Json.member "alg" |> Json.to_string_option
      |> Option.map Jwa.alg_of_string
    in
    (* TODO: This is needed if we want more curves *)
    let _crv = json |> Json.member "crv" |> Json.to_string in
    let d = json |> Json.member "d" |> Json.to_string |> U_Base64.url_decode in
    let make_jwk key =
      {
        alg;
        kty = `OKP;
        (* Shortcut since that is the only thing we handle *)
        use =
          json |> Json.member "use" |> Json.to_string_option
          |> Option.map use_of_string;
        key;
        kid = json |> Json.member "kid" |> Json.to_string_option;
      }
    in
    Result.bind d (fun str ->
        Mirage_crypto_ec.Ed25519.priv_of_octets str
        |> Result.map_error (fun _ -> `Msg "Could not create key"))
    |> Result.map (fun key -> Ed25519_priv (make_jwk key))
  with Json.Type_error (s, _) -> Error (`Json_parse_failed s)

let of_pub_json (json : Yojson.Safe.t) : (public t, 'error) result =
  let module Json = Yojson.Safe.Util in
  let kty = json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string in
  match kty with
  | `RSA -> pub_rsa_of_json json
  | `oct -> oct_of_json json
  | `EC -> pub_ec_of_json json
  | `OKP -> pub_okp_of_json json
  | _ -> Error `Unsupported_kty

let of_pub_json_string str : (public t, 'error) result =
  try Yojson.Safe.from_string str |> of_pub_json
  with Yojson.Json_error s -> Error (`Json_parse_failed s)

let of_priv_json json : (priv t, 'error) result =
  let module Json = Yojson.Safe.Util in
  let kty = json |> Json.member "kty" |> Json.to_string |> Jwa.kty_of_string in
  match kty with
  | `RSA -> priv_rsa_of_json json
  | `oct -> oct_of_json json
  | `EC -> priv_ec_of_json json
  | `OKP -> priv_okp_of_json json
  | _ -> Error `Unsupported_kty

let of_priv_json_string str : (priv t, 'error) result =
  try Yojson.Safe.from_string str |> of_priv_json
  with Yojson.Json_error s -> Error (`Json_parse_failed s)

let pub_of_priv (jwk : priv t) : public t =
  match jwk with
  | Oct oct -> Oct oct
  | Rsa_priv rsa -> Rsa_pub (pub_of_priv_rsa rsa)
  | Es256_priv es -> Es256_pub (pub_of_priv_es256 es)
  | Es384_priv es -> Es384_pub (pub_of_priv_es384 es)
  | Es512_priv es -> Es512_pub (pub_of_priv_es512 es)
  | Ed25519_priv okt -> Ed25519_pub (pub_of_priv_ed25519 okt)

let oct_to_sign_key (oct : oct) : (string, [> `Msg of string ]) result =
  U_Base64.url_decode oct.key

let hash_values hash values =
  let module Hash = (val Digestif.module_of_hash' hash) in
  `Assoc (List.filter_map Fun.id values)
  |> Yojson.to_string |> Hash.digest_string |> Hash.to_raw_string

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

let pub_es256_to_thumbprint hash (pub_es256 : pub_es256) =
  let crv = "P-256" in
  let kty = Jwa.kty_to_string pub_es256.kty in
  let x, y = Util.get_ES256_x_y pub_es256.key in
  let values =
    [
      Some ("crv", `String crv);
      Some ("kty", `String kty);
      Some ("x", `String x);
      Some ("y", `String y);
    ]
  in
  hash_values hash values

let priv_es256_to_thumbprint hash (priv_es256 : priv_es256) =
  pub_of_priv_es256 priv_es256 |> pub_es256_to_thumbprint hash

let pub_es384_to_thumbprint hash (pub_es384 : pub_es384) =
  let crv = "P-384" in
  let kty = Jwa.kty_to_string pub_es384.kty in
  let x, y = Util.get_ES384_x_y pub_es384.key in
  let values =
    [
      Some ("crv", `String crv);
      Some ("kty", `String kty);
      Some ("x", `String x);
      Some ("y", `String y);
    ]
  in
  hash_values hash values

let priv_es384_to_thumbprint hash (priv_es384 : priv_es384) =
  pub_of_priv_es384 priv_es384 |> pub_es384_to_thumbprint hash

let pub_es512_to_thumbprint hash (pub_es512 : pub_es512) =
  let crv = "P-521" in
  let kty = Jwa.kty_to_string pub_es512.kty in
  let x, y = Util.get_ES512_x_y pub_es512.key in
  let values =
    [
      Some ("crv", `String crv);
      Some ("kty", `String kty);
      Some ("x", `String x);
      Some ("y", `String y);
    ]
  in
  hash_values hash values

let priv_es512_to_thumbprint hash (priv_es512 : priv_es512) =
  pub_of_priv_es512 priv_es512 |> pub_es512_to_thumbprint hash

let pub_ed25519_to_thumbprint hash (pub_ed25519 : pub_ed25519) =
  let kty = Jwa.kty_to_string pub_ed25519.kty in
  let x =
    Mirage_crypto_ec.Ed25519.pub_to_octets pub_ed25519.key
    |> U_Base64.url_encode_string
  in
  let values =
    [
      Some ("crv", `String "Ed25519");
      Some ("kty", `String kty);
      Some ("x", `String x);
    ]
  in
  hash_values hash values

let priv_ed25519_to_thumbprint hash (priv_ed25519 : priv_ed25519) =
  pub_of_priv_ed25519 priv_ed25519 |> pub_ed25519_to_thumbprint hash

let get_thumbprint (type a) (hash : Digestif.hash') (jwk : a t) =
  match jwk with
  | Rsa_pub rsa -> Ok (pub_rsa_to_thumbprint hash rsa)
  | Rsa_priv rsa -> Ok (priv_rsa_to_thumbprint hash rsa)
  | Es256_pub ec -> Ok (pub_es256_to_thumbprint hash ec)
  | Es256_priv ec -> Ok (priv_es256_to_thumbprint hash ec)
  | Es384_pub ec -> Ok (pub_es384_to_thumbprint hash ec)
  | Es384_priv ec -> Ok (priv_es384_to_thumbprint hash ec)
  | Es512_pub ec -> Ok (pub_es512_to_thumbprint hash ec)
  | Es512_priv ec -> Ok (priv_es512_to_thumbprint hash ec)
  | Ed25519_pub okt -> Ok (pub_ed25519_to_thumbprint hash okt)
  | Ed25519_priv okt -> Ok (priv_ed25519_to_thumbprint hash okt)
  | Oct oct -> oct_to_thumbprint hash oct
