open Utils

type signature = string

type t = { header : Header.t; payload : string; signature : signature }

let verify_RS256 ~jwk str =
  Jwk.Pub.to_pub jwk
  |> RResult.map (fun key -> Nocrypto.Rsa.PKCS1.sig_decode ~key str)
  |> RResult.flat_map (function
       | None -> Error (`Msg "Could not decode signature")
       | Some message -> Ok message)

let verify_HS256 jwk str = Nocrypto.Hash.SHA256.hmac ~key:jwk str

let verify_internal ~jwk t =
  Header.to_string t.header
  |> RResult.flat_map (fun header_str ->
         let input_str = header_str ^ "." ^ t.payload in
         t.signature |> RBase64.base64_url_decode
         |> RResult.map Cstruct.of_string
         |> RResult.flat_map (verify_RS256 ~jwk)
         |> RResult.map (fun message ->
                let token_hash =
                  input_str |> Cstruct.of_string |> Nocrypto.Hash.SHA256.digest
                in
                Cstruct.equal message token_hash))

let validate ~(jwks : Jwks.t) t =
  let header = t.header in
  ( match header.alg with
  | `RS256 -> Ok header.alg
  | `HS256 -> Ok header.alg
  | _ -> Error (`Msg "alg must be RS256") )
  |> RResult.flat_map (fun _ ->
         RList.find_opt
           (fun (jwk : Jwk.Pub.t) ->
             jwk.kid = CCOpt.get_or ~default:"" header.kid)
           jwks.keys
         |> function
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
