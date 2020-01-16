open Utils

type signature = string

type t = { header : Header.t; payload : string; signature : signature }

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

let validate ~(jwks : Jwks.t) t =
  let find_jwk = Jwks.find_key jwks in
  let header = t.header in
  ( match header.alg with
  | `RS256 -> Ok header.alg
  | `HS256 -> Ok header.alg
  | _ -> Error (`Msg "alg must be RS256 or HS256") )
  |> RResult.flat_map (fun _ ->
         find_jwk (ROpt.get_or ~default:"" header.kid) |> function
         | Some jwk -> Ok jwk
         | None -> Error (`Msg "Did not find key with correct kid"))
  |> RResult.flat_map (fun jwk -> verify_internal ~jwk t)
  |> RResult.map (fun _ -> t)

let sign ~header ~payload key =
  Header.to_string header
  |> RResult.flat_map (fun header_str ->
         let input_str = header_str ^ "." ^ payload in
         `Message (Cstruct.of_string input_str)
         |> Nocrypto.Rsa.PKCS1.sign ~hash:`SHA256 ~key
         |> Cstruct.to_string |> RBase64.base64_url_encode
         |> RResult.map (fun sign -> (header, payload, sign)))
  |> RResult.map (fun (header, payload, signature) ->
         { header; payload; signature })
