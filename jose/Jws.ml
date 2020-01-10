open Utils

type signature = string

type t = { header : Header.t; payload : string; signature : signature }

let verify_internal ~pub_key t =
  Header.to_string t.header
  |> RResult.flat_map (fun header_str ->
         let input_str = header_str ^ "." ^ t.payload in
         t.signature |> RBase64.base64_url_decode
         |> RResult.map Cstruct.of_string
         |> RResult.map (fun s ->
                match Nocrypto.Rsa.PKCS1.sig_decode ~key:pub_key s with
                | None -> (
                    Error (`Msg "Could not decode signature") [@explicit_arity]
                    )
                | ((Some message)[@explicit_arity]) ->
                    let token_hash =
                      input_str |> Cstruct.of_string
                      |> Nocrypto.Hash.SHA256.digest
                    in
                    (Ok (Cstruct.equal message token_hash) [@explicit_arity])))

let validate ~(jwks : Jwks.t) t =
  let header = t.header in
  ( match header.alg with
  | `RS256 -> ( Ok header.alg [@explicit_arity] )
  | _ -> ( Error (`Msg "alg must be RS256") [@explicit_arity] ) )
  |> RResult.flat_map (fun _ ->
         RList.find_opt
           (fun (jwk : Jwk.Pub.t) ->
             jwk.kid = CCOpt.get_or ~default:"" header.kid)
           jwks.keys
         |> function
         | ((Some jwk)[@explicit_arity]) -> ( Ok jwk [@explicit_arity] )
         | None -> (
             Error (`Msg "Did not find key with correct kid") [@explicit_arity]
             ))
  |> RResult.flat_map Jwk.Pub.to_pub
  |> RResult.flat_map (fun pub_key -> verify_internal ~pub_key t)
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
