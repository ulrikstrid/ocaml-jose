open Utils

type signature = string

type t = { header : Header.t; payload : string; signature : signature }

let of_string token =
  String.split_on_char '.' token |> function
  | [ header_str; payload_str; signature ] ->
      let header = Header.of_string header_str in
      let payload = payload_str |> RBase64.base64_url_decode in
      RResult.both header payload
      |> RResult.map (fun (header, payload) -> { header; payload; signature })
  | _ -> Error (`Msg "token didn't include header, payload or signature")

let to_string t =
  let header_str = Header.to_string t.header in
  let payload_str = t.payload |> RBase64.base64_url_encode in
  RResult.both header_str payload_str
  |> RResult.map (fun (header_str, payload_str) ->
         header_str ^ "." ^ payload_str ^ "." ^ t.signature)

let verify_RS256 ~jwk str =
  match jwk with
  | Jwk.Pub.RSA jwk ->
      Jwk.Pub.rsa_to_pub jwk
      |> RResult.map (fun key -> Nocrypto.Rsa.PKCS1.sig_decode ~key str)
      |> RResult.flat_map (function
           | None -> Error (`Msg "Could not decode signature")
           | Some message -> Ok message)
  | _ -> Error (`Msg "JWK doesn't match")

let verify_HS256 ~jwk str =
  match jwk with
  | Jwk.Pub.OCT jwk ->
      Jwk.Pub.oct_to_key jwk |> fun key ->
      Nocrypto.Hash.SHA256.hmac ~key str |> RResult.return
  | _ -> Error (`Msg "JWK doesn't match")

let verify_jwk ~(jwk : Jwk.Pub.t) str =
  match Jwk.Pub.get_alg jwk with
  | `RS256 -> verify_RS256 ~jwk str
  | `HS256 -> verify_HS256 ~jwk str
  | `none -> Ok str
  | _ -> Error (`Msg "alg not supported")

let verify_internal ~jwk t =
  Header.to_string t.header
  |> RResult.flat_map (fun header_str ->
         let input_str = header_str ^ "." ^ t.payload in
         t.signature |> RBase64.base64_url_decode
         |> RResult.map Cstruct.of_string
         |> RResult.flat_map (verify_jwk ~jwk)
         |> RResult.map (fun message ->
                let token_hash =
                  input_str |> Cstruct.of_string |> Nocrypto.Hash.SHA256.digest
                in
                Cstruct.equal message token_hash))

let validate ~(jwk : Jwk.Pub.t) t =
  let header = t.header in
  ( match header.alg with
  | `RS256 -> Ok header.alg
  | `HS256 -> Ok header.alg
  | _ -> Error (`Msg "alg must be RS256 or HS256") )
  |> RResult.flat_map (fun _ -> verify_internal ~jwk t)
  |> RResult.map (fun _ -> t)

(* Assumes a well formed header. *)
let sign ~header ~payload (key : Jwk.Priv.t) =
  let sign_f =
    match key with
    | Jwk.Priv.RSA k -> (
        match Jwk.Priv.rsa_to_priv k with
        | Ok key -> Ok (fun x -> Nocrypto.Rsa.PKCS1.sign ~hash:`SHA256 ~key x)
        | Error e -> Error e )
    | OCT oct ->
        Ok
          (fun [@ocaml.warning "-8"] (`Message x) ->
            Nocrypto.Hash.SHA256.hmac ~key:(Jwk.Oct.oct_to_key oct) x)
  in
  match sign_f with
  | Ok sign_f ->
      RResult.both (Header.to_string header) (RBase64.base64_url_encode payload)
      |> RResult.flat_map (fun (header_str, payload_str) ->
             let input_str = header_str ^ "." ^ payload_str in
             `Message (Cstruct.of_string input_str)
             |> sign_f |> Cstruct.to_string |> RBase64.base64_url_encode)
      |> RResult.map (fun signature -> { header; payload; signature })
  | Error e -> Error e
