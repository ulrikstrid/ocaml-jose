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
    |> Base64.encode_exn ~pad:false ~alphabet:Base64.uri_safe_alphabet

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

type oct = { kty : Jwa.kty; alg : Jwa.alg; use : string option; key : string }

type priv_rsa = {
  alg : Jwa.alg;
  kty : Jwa.kty;
  use : string option;
  key : Mirage_crypto_pk.Rsa.priv;
}

type pub_rsa = {
  alg : Jwa.alg;
  kty : Jwa.kty;
  use : string option;
  key : Mirage_crypto_pk.Rsa.pub;
}

type _ t =
  | Oct : oct -> priv t
  | Rsa_priv : priv_rsa -> priv t
  | Rsa_pub : pub_rsa -> public t

let get_alg (type a) (t : a t) =
  match t with
  | Rsa_priv rsa -> rsa.alg
  | Rsa_pub rsa -> rsa.alg
  | Oct oct -> oct.alg

let get_kty (type a) (t : a t) =
  match t with Rsa_priv _ -> `RSA | Rsa_pub _ -> `RSA | Oct _ -> `oct

let make_oct ?(use : string option) (str : string) : priv t =
  let key =
    Base64.encode_exn ~pad:false ~alphabet:Base64.uri_safe_alphabet str
  in
  Oct { kty = `oct; use; alg = `HS256; key }

let make_priv_rsa ?(use : string option) (rsa_priv : Mirage_crypto_pk.Rsa.priv)
    : priv t =
  Rsa_priv { alg = `RS256; kty = `RSA; use; key = rsa_priv }

let make_pub_rsa ?(use : string option) (rsa_pub : Mirage_crypto_pk.Rsa.pub) :
    public t =
  Rsa_pub { alg = `RS256; kty = `RSA; use; key = rsa_pub }

let oct_to_json (oct : oct) =
  `Assoc
    [
      ("alg", Jwa.alg_to_json oct.alg);
      ("kty", `String (Jwa.kty_to_string oct.kty));
      ("k", `String oct.key);
      ("kid", `String (Util.get_OCT_kid oct.key));
    ]

let pub_rsa_to_json pub_rsa =
  let public_key : X509.Public_key.t = `RSA pub_rsa.key in
  let e = Util.get_JWK_component pub_rsa.key.e |> RResult.to_opt in
  let n = Util.get_JWK_component pub_rsa.key.n |> RResult.to_opt in
  let values =
    [
      Some ("alg", Jwa.alg_to_json pub_rsa.alg);
      RJson.to_json_string_opt "e" e;
      RJson.to_json_string_opt "n" n;
      Some ("kty", `String (Jwa.kty_to_string pub_rsa.kty));
      ROpt.both e n
      |> ROpt.map (fun (e, n) -> Util.get_RSA_kid ~e ~n)
      |> RJson.to_json_string_opt "kid";
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

let to_pub_json (type a) (jwk : a t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_pub_json rsa
  | Rsa_pub rsa -> pub_rsa_to_json rsa

let to_priv_json (jwk : priv t) : Yojson.Safe.t =
  match jwk with
  | Oct oct -> oct_to_json oct
  | Rsa_priv rsa -> priv_rsa_to_pub_json rsa
