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
  | [ header_str; payload_str; signature ] -> (
      let header = Header.of_string header_str in
      let payload = payload_str |> U_Base64.url_decode in
      match (header, payload) with
      | Ok header, Ok payload ->
          Ok { header; raw_header = header_str; payload; signature }
      | Error e, _ | _, Error e -> Error e)
  | _ -> Error (`Msg "token didn't include header, payload or signature")

let of_json_string token =
  try
    let module Json = Yojson.Safe.Util in
    let json = Yojson.Safe.from_string token in
    let payload =
      let payload =
        Json.member "payload" json |> Json.to_string_option
        |> Option.to_result ~none:(`Msg "no payload")
      in
      Result.bind payload U_Base64.url_decode
    in

    match (payload, Json.member "signature" json |> Json.to_string_option) with
    | Ok payload, Some signature ->
        let protected = Json.member "protected" json |> Json.to_string in
        Ok
          {
            header = Header.of_string protected |> Result.get_ok;
            raw_header = protected;
            payload;
            signature;
          }
    | Error e, _ -> Error e
    | _, None -> Error `Not_supported
  with _ -> Error `Not_json

let of_string token =
  (* If the first char is '{' we assume it's JSON since a compact representation starts with ey *)
  match String.index_opt token '{' with
  | Some 0 -> of_json_string token
  | _ -> of_compact_string token

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

let verify_jwk (type a) ~(jwk : a Jwk.t) ~input_str signature =
  match jwk with
  | Jwk.Rsa_priv jwk -> (
      let pub_jwk = Jwk.pub_of_priv_rsa jwk in
      Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:pub_jwk.key signature
      |> function
      | None -> Error `Invalid_signature
      | Some message -> Ok message)
  | Jwk.Rsa_pub jwk -> (
      Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:jwk.key signature |> function
      | None -> Error `Invalid_signature
      | Some message -> Ok message)
  | Jwk.Oct jwk ->
      let key = Jwk.oct_to_sign_key jwk in
      Result.bind key (fun key ->
          let computed_signature =
            Digestif.SHA256.hmac_string ~key input_str
            |> Digestif.SHA256.to_raw_string
          in
          (* From RFC7518§3.2:
           *   The comparison of the computed HMAC value to the JWS Signature
           *   value MUST be done in a constant-time manner to thwart timing
           *   attacks. *)
          if Eqaf.equal signature computed_signature then Ok computed_signature
          else Error `Invalid_signature)
  | Jwk.Es256_pub pub_jwk ->
      let r, s = U_String.split signature 32 in
      let message =
        Digestif.SHA256.digest_string input_str |> Digestif.SHA256.to_raw_string
      in
      if Mirage_crypto_ec.P256.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok signature
      else Error `Invalid_signature
  | Jwk.Es256_priv jwk ->
      let r, s = U_String.split signature 32 in
      let message =
        Digestif.SHA256.digest_string input_str |> Digestif.SHA256.to_raw_string
      in
      let pub_jwk = Jwk.pub_of_priv_es256 jwk in
      if Mirage_crypto_ec.P256.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok signature
      else Error `Invalid_signature
  | Jwk.Es384_pub pub_jwk ->
      let r, s = U_String.split signature 48 in
      let message =
        Digestif.SHA384.digest_string input_str |> Digestif.SHA384.to_raw_string
      in
      if Mirage_crypto_ec.P384.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok signature
      else Error `Invalid_signature
  | Jwk.Es384_priv jwk ->
      let r, s = U_String.split signature 48 in
      let message =
        Digestif.SHA384.digest_string input_str |> Digestif.SHA384.to_raw_string
      in
      let pub_jwk = Jwk.pub_of_priv_es384 jwk in
      if Mirage_crypto_ec.P384.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok signature
      else Error `Invalid_signature
  | Jwk.Es512_pub pub_jwk ->
      let r, s = U_String.split signature 66 in
      let message =
        Digestif.SHA512.digest_string input_str |> Digestif.SHA512.to_raw_string
      in
      if Mirage_crypto_ec.P521.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok signature
      else Error `Invalid_signature
  | Jwk.Es512_priv jwk ->
      let r, s = U_String.split signature 66 in
      let message =
        Digestif.SHA512.digest_string input_str |> Digestif.SHA512.to_raw_string
      in
      let pub_jwk = Jwk.pub_of_priv_es512 jwk in
      if Mirage_crypto_ec.P521.Dsa.verify ~key:pub_jwk.key (r, s) message then
        Ok signature
      else Error `Invalid_signature
  | Jwk.Ed25519_priv jwk ->
      let key = Mirage_crypto_ec.Ed25519.pub_of_priv jwk.key in
      let msg = input_str in
      if Mirage_crypto_ec.Ed25519.verify ~key signature ~msg then Ok signature
      else Error `Invalid_signature
  | Jwk.Ed25519_pub jwk ->
      let msg = input_str in
      if Mirage_crypto_ec.Ed25519.verify ~key:jwk.key signature ~msg then
        Ok signature
      else Error `Invalid_signature

let verify_internal (type a) ~(jwk : a Jwk.t) t =
  let payload_str = U_Base64.url_encode_string t.payload in
  let input_str = Printf.sprintf "%s.%s" t.raw_header payload_str in
  let unverified_jwk = U_Base64.url_decode t.signature in
  Result.bind unverified_jwk (verify_jwk ~jwk ~input_str)

let validate (type a) ~(jwk : a Jwk.t) t =
  let header = t.header in
  let alg =
    match header.alg with
    | `RS256 -> Ok header.alg
    | `HS256 -> Ok header.alg
    | `ES256 -> Ok header.alg
    | `ES384 -> Ok header.alg
    | `ES512 -> Ok header.alg
    | `EdDSA -> Ok header.alg
    | `Unsupported _ | `RSA_OAEP | `RSA1_5 | `None ->
        Error (`Msg "alg not supported for signing")
  in
  Result.bind alg (fun _alg ->
      match verify_internal ~jwk t with Ok _sig -> Ok t | Error e -> Error e)

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
              let message =
                Digestif.SHA256.digest_string x |> Digestif.SHA256.to_raw_string
              in
              let r, s = Mirage_crypto_ec.P256.Dsa.sign ~key message in
              r ^ s
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Es384_priv { key; _ } ->
        Ok
          (function
          | `Message x ->
              let message =
                Digestif.SHA384.digest_string x |> Digestif.SHA384.to_raw_string
              in
              let r, s = Mirage_crypto_ec.P384.Dsa.sign ~key message in
              r ^ s
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Es512_priv { key; _ } ->
        Ok
          (function
          | `Message x ->
              let message =
                Digestif.SHA512.digest_string x |> Digestif.SHA512.to_raw_string
              in
              let r, s = Mirage_crypto_ec.P521.Dsa.sign ~key message in
              r ^ s
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Ed25519_priv jwk ->
        Ok
          (function
          | `Message x -> Mirage_crypto_ec.Ed25519.sign ~key:jwk.key x
          | `Digest _ -> raise (Invalid_argument "Digest"))
    | Jwk.Oct oct ->
        Jwk.oct_to_sign_key oct
        |> Result.map (fun key msg ->
               match msg with
               | `Message x ->
                   Digestif.SHA256.hmac_string ~key x
                   |> Digestif.SHA256.to_raw_string
               | `Digest _ -> raise (Invalid_argument "Digest"))
  in
  match sign_f with
  | Ok sign_f ->
      let header_str = Header.to_string header in
      let payload_str = U_Base64.url_encode_string payload in
      let input_str = Printf.sprintf "%s.%s" header_str payload_str in
      let signature =
        `Message input_str |> sign_f |> U_Base64.url_encode_string
      in
      Ok { header; raw_header = header_str; payload; signature }
  | Error e -> Error e
