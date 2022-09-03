open Utils

type signature = string

type t = {
  header : Header.t;
  raw_header : string;
  payload : string;
  signature : signature;
}

let of_string token =
  String.split_on_char '.' token |> function
  | [ header_str; payload_str; signature ] ->
      let header = Header.of_string header_str in
      let payload = payload_str |> U_Base64.url_decode in
      U_Result.both header payload
      |> U_Result.map (fun (header, payload) ->
             { header; raw_header = header_str; payload; signature })
  | _ -> Error (`Msg "token didn't include header, payload or signature")

let to_string t =
  let payload_str = t.payload |> U_Base64.url_encode_string in
  Printf.sprintf "%s.%s.%s" t.raw_header payload_str t.signature

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
      Mirage_crypto.Hash.SHA256.hmac ~key:(Cstruct.of_string jwk.key) str
      |> U_Result.return
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

let verify_internal (type a) ~(jwk : a Jwk.t) t =
  let payload_str = U_Base64.url_encode_string t.payload in
  let input_str = Printf.sprintf "%s.%s" t.raw_header payload_str in
  U_Base64.url_decode t.signature
  |> U_Result.map Cstruct.of_string
  |> U_Result.flat_map (verify_jwk ~jwk ~input_str)
  |> U_Result.map (fun message ->
         let token_hash =
           input_str |> Cstruct.of_string |> Mirage_crypto.Hash.SHA256.digest
         in
         (* From RFC7518§3.2:
          *   The comparison of the computed HMAC value to the JWS Signature
          *   value MUST be done in a constant-time manner to thwart timing
          *   attacks. *)
         Eqaf_cstruct.equal message token_hash)

let validate (type a) ~(jwk : a Jwk.t) t =
  let header = t.header in
  (match header.alg with
  | `RS256 -> Ok header.alg
  | `HS256 -> Ok header.alg
  | `ES256 -> Ok header.alg
  | `ES512 -> Ok header.alg
  | `Unsupported _ | `RSA_OAEP | `RSA1_5 | `None ->
      Error (`Msg "alg not supported for signing"))
  |> U_Result.flat_map (fun _ -> verify_internal ~jwk t)
  |> U_Result.map (fun _ -> t)

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
    | Jwk.Es512_priv { key; _ } ->
        Ok
          (function
          | `Message x ->
              let message = Mirage_crypto.Hash.SHA512.digest x in
              let r, s = Mirage_crypto_ec.P521.Dsa.sign ~key message in
              let sign = Cstruct.append r s in
              sign
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
