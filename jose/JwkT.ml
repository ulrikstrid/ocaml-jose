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

  let get_OCT_kid ~k =
    `Assoc [ ("k", `String k); ("kty", `String "oct") ] |> kid_of_json

  let get_JWK_x5t fingerprint =
    fingerprint |> Cstruct.to_bytes |> Bytes.to_string
    |> RBase64.url_encode ~len:20
end

type priv_jwk

type pub_jwk

type typ = [ `Priv | `Pub ]

type use = [ `Sign | `Encode ]
(** The "use" (public key use) parameter identifies the intended use of
   the public key.  The "use" parameter is employed to indicate whether
   a public key is used for encrypting data or verifying the signature
   on data. 
   
   {{:  https://tools.ietf.org/html/rfc7517#section-4.2 } Link to RFC }
   *)

type 'typ oct = {
  kty : Jwa.kty;
  alg : Jwa.alg;  (** `oct *)
  kid : string;  (** `HS256 *)
  k : string;
}

type 'typ rsa = {
  alg : Jwa.alg;  (** `RSA *)
  kty : Jwa.kty;  (** `RS256 *)
  use : use option;  (** only avaialble in public *)
  n : string;
  e : string;
  d : string;  (** only avaialble in private *)
  p : string;  (** only avaialble in private *)
  q : string;  (** only avaialble in private *)
  dp : string;  (** only avaialble in private *)
  dq : string;  (** only avaialble in private *)
  qi : string;  (** only avaialble in private *)
  kid : string;
  x5t : string option;
}

type 'typ t = OCT of 'typ oct | RSA of 'typ rsa

let use_to_string use = match use with `Sign -> "sig" | `Encode -> "enc"

let get_kid t = match t with RSA rsa -> rsa.kid | OCT oct -> oct.kid

let get_alg t = match t with RSA rsa -> rsa.alg | OCT oct -> oct.alg

let get_kty t = match t with RSA _ -> `RSA | OCT _ -> `oct

let pub_rsa_to_json (rsa : 'typ rsa) =
  let values =
    [
      Some ("alg", Jwa.alg_to_json rsa.alg);
      Some ("e", `String rsa.e);
      Some ("n", `String rsa.n);
      Some ("kty", `String (Jwa.kty_to_string rsa.kty));
      Some ("kid", `String rsa.kid);
      RJson.to_json_string_opt "use" (rsa.use |> Option.map use_to_string);
      RJson.to_json_string_opt "x5t" rsa.x5t;
    ]
  in
  `Assoc (RList.filter_map (fun x -> x) values)

let priv_rsa_to_json (rsa : priv_jwk rsa) =
  `Assoc
    [
      ("alg", Jwa.alg_to_json rsa.alg);
      ("e", `String rsa.e);
      ("n", `String rsa.n);
      ("d", `String rsa.d);
      ("p", `String rsa.p);
      ("q", `String rsa.q);
      ("dp", `String rsa.dp);
      ("dq", `String rsa.dq);
      ("qi", `String rsa.qi);
      ("kty", `String (rsa.kty |> Jwa.kty_to_string));
      ("kid", `String rsa.kid);
    ]

let oct_to_json (oct : 'typ oct) =
  `Assoc
    [
      ("alg", Jwa.alg_to_json oct.alg);
      ("kty", `String (Jwa.kty_to_string oct.kty));
      ("k", `String oct.k);
      ("kid", `String oct.kid);
    ]

let priv_to_json (t : priv_jwk t) =
  match t with RSA rsa -> priv_rsa_to_json rsa | OCT oct -> oct_to_json oct

let pub_to_json (t : pub_jwk t) =
  match t with RSA rsa -> pub_rsa_to_json rsa | OCT oct -> oct_to_json oct
