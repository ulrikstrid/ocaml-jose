open Utils

type signature = string

type t = { header : Header.t; payload : string; signature : signature }

let of_string token =
  String.split_on_char '.' token |> function
  | [ header_str; payload_str; signature ] ->
      let header = Header.of_string header_str in
      let payload = payload_str |> RBase64.url_decode in
      RResult.both header payload
      |> RResult.map (fun (header, payload) -> { header; payload; signature })
  | _ -> Error (`Msg "token didn't include header, payload or signature")

let to_string t =
  let header_str = Header.to_string t.header in
  let payload_str = t.payload |> RBase64.url_encode_string in
  header_str ^ "." ^ payload_str ^ "." ^ t.signature

let verify_RS256 (type a) ~(jwk : a Jwk.t) str =
  ( match jwk with
  | Jwk.Rsa_priv jwk ->
      let pub_jwk = Jwk.pub_of_priv_rsa jwk in
      Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:pub_jwk.key str
  | Jwk.Rsa_pub jwk -> Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:jwk.key str
  | Jwk.Oct _ -> None )
  |> function
  | None -> Error `Invalid_signature
  | Some message -> Ok message

let verify_HS256 (type a) ~(jwk : a Jwk.t) str =
  match jwk with
  | Jwk.Oct jwk ->
      Mirage_crypto.Hash.SHA256.hmac ~key:(Cstruct.of_string jwk.key) str
      |> RResult.return
  | _ -> Error (`Msg "JWK doesn't match")

let verify_jwk (type a) ~(jwk : a Jwk.t) str =
  match Jwk.get_alg jwk with
  | `RS256 -> verify_RS256 ~jwk str
  | `HS256 -> verify_HS256 ~jwk str
  | `None -> Ok str
  | _ -> Error (`Msg "alg not supported")

let verify_internal (type a) ~(jwk : a Jwk.t) t =
  let header_str = Header.to_string t.header in
  let input_str = header_str ^ "." ^ t.payload in
  t.signature |> RBase64.url_decode
  |> RResult.map Cstruct.of_string
  |> RResult.flat_map (verify_jwk ~jwk)
  |> RResult.map (fun message ->
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
  ( match header.alg with
  | `RS256 -> Ok header.alg
  | `HS256 -> Ok header.alg
  | `Unsupported _ | `RSA_OAEP | `RSA1_5 | `None ->
      Error (`Msg "alg must be RS256 or HS256") )
  |> RResult.flat_map (fun _ -> verify_internal ~jwk t)
  |> RResult.map (fun _ -> t)

(* Assumes a well formed header. *)
let sign ~(header : Header.t) ~payload (jwk : Jwk.priv Jwk.t) =
  let sign_f =
    match jwk with
    | Jwk.Rsa_priv { key; _ } ->
        Ok (fun x -> Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:`SHA256 ~key x)
    | Jwk.Oct oct ->
        Jwk.oct_to_sign_key oct
        |> RResult.map (fun key ->
             function
             | `Message x -> Mirage_crypto.Hash.SHA256.hmac ~key x
             | `Digest _ -> raise (Invalid_argument "Digest"))
  in
  match sign_f with
  | Ok sign_f ->
      let header_str = Header.to_string header in
      let payload_str = RBase64.url_encode_string payload in
      let input_str = header_str ^ "." ^ payload_str in
      let signature =
        `Message (Cstruct.of_string input_str)
        |> sign_f |> Cstruct.to_string |> RBase64.url_encode_string
      in
      Ok { header; payload; signature }
  | Error e -> Error e
