open Utils

type signature = string

type t = {
  header : Header.t; (* TODO: This is always treated as protected headers*)
  raw_header : string;
  payload : string;
  signature : signature;
}

type serialization = [ `Compact | `General | `Flattened ]

let of_compact_string token =
  String.split_on_char '.' token |> function
  | [ header_str; payload_str; signature ] ->
      let header = Header.of_string header_str in
      let payload = payload_str |> U_Base64.url_decode in
      U_Result.both header payload
      |> U_Result.map (fun (header, payload) ->
             { header; raw_header = header_str; payload; signature })
  | _ -> Error (`Msg "token didn't include header, payload or signature")

let of_json_string token =
  try
    let module Json = Yojson.Safe.Util in
    let json = Yojson.Safe.from_string token in
    let payload =
      Json.member "payload" json |> Json.to_string |> U_Base64.url_decode
    in

    match (payload, Json.member "signature" json |> Json.to_string_option) with
    | Ok payload, Some signature ->
        let protected = Json.member "protected" json |> Json.to_string in
        Ok
          {
            header = Header.of_string protected |> U_Result.get_exn;
            raw_header = protected;
            payload;
            signature;
          }
    | Error e, _ -> Error e
    | _, None -> Error `Not_supported
  with _ -> Error `Not_json

let of_string token =
  match of_json_string token with
  | Ok t -> Ok t
  | Error `Not_json -> of_compact_string token
  | e -> e

let to_flattened_json t =
  let payload_str = t.payload |> U_Base64.url_encode_string in
  `Assoc
    [
      ("payload", `String payload_str);
      ("protected", `String t.raw_header);
      (* TODO: add "header" for public header parameters *)
      ("signature", `String t.signature);
    ]

let to_compact_string t =
  let payload_str = t.payload |> U_Base64.url_encode_string in
  Printf.sprintf "%s.%s.%s" t.raw_header payload_str t.signature

let to_general_string t =
  let payload_str = t.payload |> U_Base64.url_encode_string in
  (* TODO: Support multiple signatures *)
  let signatures =
    [
      `Assoc
        [
          ("protected", `String t.raw_header);
          (* TODO: add "header" for public header parameters *)
          ("signature", `String t.signature);
        ];
    ]
  in
  `Assoc [ ("payload", `String payload_str); ("signatures", `List signatures) ]
  |> Yojson.Safe.to_string

let to_flattened_string t = to_flattened_json t |> Yojson.Safe.to_string

let to_string ?(serialization = `Compact) t =
  match serialization with
  | `Compact -> to_compact_string t
  | `General -> to_general_string t
  | `Flattened -> to_flattened_string t

let verify_jwk (type a) ~(jwk : a Jwk.t) ~input_str str =
  match jwk with
  | Jwk.Rsa_priv jwk -> (
      let pub_jwk = Jwk.pub_of_priv_rsa jwk in
      Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:pub_jwk.key str |> function
      | None -> Error `Invalid_signature
      | Some message -> Ok message)
  | Jwk.Rsa_pub jwk -> (
      Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:jwk.key str |> function
      | None -> Error `Invalid_signature
      | Some message -> Ok message)
  | Jwk.Oct jwk ->
      Jwk.oct_to_sign_key jwk
      |> U_Result.flat_map (fun key ->
             let computed_signature =
               Mirage_crypto.Hash.SHA256.hmac ~key (Cstruct.of_string input_str)
             in
             (* From RFC7518§3.2:
              *   The comparison of the computed HMAC value to the JWS Signature
              *   value MUST be done in a constant-time manner to thwart timing
              *   attacks. *)
             if Eqaf_cstruct.equal str computed_signature then
               Ok computed_signature
             else Error `Invalid_signature)
  | Jwk.Es256_pub pub_jwk ->
      let r, s = Cstruct.split str 32 in
      let message =
        Mirage_crypto.Hash.SHA256.digest (Cstruct.of_string input_str)
      in
      if Mirage_crypto_ec.P256.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok str
      else Error `Invalid_signature
  | Jwk.Es256_priv jwk ->
      let r, s = Cstruct.split str 32 in
      let message =
        Mirage_crypto.Hash.SHA256.digest (Cstruct.of_string input_str)
      in
      let pub_jwk = Jwk.pub_of_priv_es256 jwk in
      if Mirage_crypto_ec.P256.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok str
      else Error `Invalid_signature
  | Jwk.Es384_pub pub_jwk ->
      let r, s = Cstruct.split str 48 in
      let message =
        Mirage_crypto.Hash.SHA384.digest (Cstruct.of_string input_str)
      in
      if Mirage_crypto_ec.P384.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok str
      else Error `Invalid_signature
  | Jwk.Es384_priv jwk ->
      let r, s = Cstruct.split str 48 in
      let message =
        Mirage_crypto.Hash.SHA384.digest (Cstruct.of_string input_str)
      in
      let pub_jwk = Jwk.pub_of_priv_es384 jwk in
      if Mirage_crypto_ec.P384.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok str
      else Error `Invalid_signature
  | Jwk.Es512_pub pub_jwk ->
      let r, s = Cstruct.split str 66 in
      let message =
        Mirage_crypto.Hash.SHA512.digest (Cstruct.of_string input_str)
      in
      if Mirage_crypto_ec.P521.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok str
      else Error `Invalid_signature
  | Jwk.Es512_priv jwk ->
      let r, s = Cstruct.split str 66 in
      let message =
        Mirage_crypto.Hash.SHA512.digest (Cstruct.of_string input_str)
      in
      let pub_jwk = Jwk.pub_of_priv_es512 jwk in
      if Mirage_crypto_ec.P521.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok str
      else Error `Invalid_signature
  | Jwk.Ed25519_priv jwk ->
      let key = Mirage_crypto_ec.Ed25519.pub_of_priv jwk.key in
      let msg = Cstruct.of_string input_str in
      if Mirage_crypto_ec.Ed25519.verify ~key str ~msg then Ok str
      else Error `Invalid_signature
  | Jwk.Ed25519_pub jwk ->
      let msg = Cstruct.of_string input_str in
      if Mirage_crypto_ec.Ed25519.verify ~key:jwk.key str ~msg then Ok str
      else Error `Invalid_signature

let verify_internal (type a) ~(jwk : a Jwk.t) t =
  let payload_str = U_Base64.url_encode_string t.payload in
  let input_str = Printf.sprintf "%s.%s" t.raw_header payload_str in
  U_Base64.url_decode t.signature
  |> U_Result.map Cstruct.of_string
  |> U_Result.flat_map (verify_jwk ~jwk ~input_str)

let validate (type a) ~(jwk : a Jwk.t) t =
  let header = t.header in
  (match header.alg with
  | `RS256 -> Ok header.alg
  | `HS256 -> Ok header.alg
  | `ES256 -> Ok header.alg
  | `ES384 -> Ok header.alg
  | `ES512 -> Ok header.alg
  | `EdDSA -> Ok header.alg
  | `Unsupported _ | `RSA_OAEP | `RSA1_5 | `None ->
      Error (`Msg "alg not supported for signing"))
  |> U_Result.flat_map (fun _alg ->
         match verify_internal ~jwk t with
         | Ok _sig -> Ok t
         | Error e -> Error e)

(* Assumes a well formed header. *)
let sign ?header ~payload (jwk : Jwk.priv Jwk.t) =
  let header =
    match header with
    | Some header -> header
    | None -> Header.make_header ~typ:"JWS" jwk
  in
  let sign_f =
    match jwk with
    | Jwk.Rsa_priv { key; _ } ->
        Ok (fun x -> Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:`SHA256 ~key x)
    | Jwk.Es256_priv { key; _ } ->
        Ok
          (function
          | `Message x ->
              let message = Mirage_crypto.Hash.SHA256.digest x in
              let r, s = Mirage_crypto_ec.P256.Dsa.sign ~key message in
              Cstruct.append r s
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Es384_priv { key; _ } ->
        Ok
          (function
          | `Message x ->
              let message = Mirage_crypto.Hash.SHA384.digest x in
              let r, s = Mirage_crypto_ec.P384.Dsa.sign ~key message in
              Cstruct.append r s
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Es512_priv { key; _ } ->
        Ok
          (function
          | `Message x ->
              let message = Mirage_crypto.Hash.SHA512.digest x in
              let r, s = Mirage_crypto_ec.P521.Dsa.sign ~key message in
              let sign = Cstruct.append r s in
              sign
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Ed25519_priv jwk ->
        Ok
          (function
          | `Message x -> Mirage_crypto_ec.Ed25519.sign ~key:jwk.key x
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Oct oct ->
        Jwk.oct_to_sign_key oct
        |> U_Result.map (fun key -> function
             | `Message x -> Mirage_crypto.Hash.SHA256.hmac ~key x
             | `Digest _ -> raise (Invalid_argument "Digest"))
  in
  match sign_f with
  | Ok sign_f ->
      let header_str = Header.to_string header in
      let payload_str = U_Base64.url_encode_string payload in
      let input_str = Printf.sprintf "%s.%s" header_str payload_str in
      let signature =
        `Message (Cstruct.of_string input_str)
        |> sign_f |> Cstruct.to_string |> U_Base64.url_encode_string
      in
      Ok { header; raw_header = header_str; payload; signature }
  | Error e -> Error e
