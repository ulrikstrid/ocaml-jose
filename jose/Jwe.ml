open Utils
(** {{:https://tools.ietf.org/html/rfc7516} Link to RFC} *)

type t = {
  header : Header.t;
  cek : string;
  iv : string;
  payload : string;
  aad : string option;
}

module RSA_OAEP = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA1)

(*
Steps to create a JWE

* Generate a random Content Encryption Key (CEK)
* Encrypt the CEK with the recipient's public key using the RSAES OAEP algorithm to produce the JWE Encrypted Key.
* Base64url encode the JWE Encrypted Key to produce the Encoded JWE Encrypted Key.
* Generate a random JWE Initialization Vector.
* Base64url encode the JWE Initialization Vector to produce the Encoded JWE Initialization Vector.
* Let the Additional Authenticated Data encryption parameter be the octets of the ASCII representation of the Encoded JWE Header value.
* Encrypt the Plaintext with AES GCM using the CEK as the encryption key, the JWE Initialization Vector, and the Additional Authenticated Data value, requesting a 128 bit Authentication Tag output.
* Base64url encode the Ciphertext to create the Encoded JWE Ciphertext.
* Base64url encode the Authentication Tag to create the Encoded JWE Authentication Tag.
* Assemble the final representation: The Compact Serialization of this result is the concatenation of the Encoded JWE Header, the Encoded JWE Encrypted Key, the Encoded JWE Initialization Vector, the Encoded JWE Ciphertext, and the Encoded JWE Authentication Tag in that order, with the five strings being separated by four period ('.') characters.
*)

let make_cek (header : Header.t) =
  match header.enc with
  | Some enc ->
      let key_length = Jwa.enc_to_length enc in
      Mirage_crypto_rng.generate (key_length / 8) |> Result.ok
  | None -> Error `Missing_enc

let make_iv (header : Header.t) =
  match header.alg with
  | `RSA_OAEP ->
      Ok (Mirage_crypto_rng.generate Mirage_crypto.AES.GCM.block_size)
  | `RSA1_5 -> Ok (Mirage_crypto_rng.generate Mirage_crypto.AES.CBC.block_size)
  | _ -> Error `Unsupported_alg

let make ~header payload =
  let cek = make_cek header in
  Result.bind cek (fun cek ->
      let iv = make_iv header in
      Result.bind iv (fun iv ->
          let aad = None in
          Ok { header; cek; iv; aad; payload }))

let encrypt_payload ?enc ~cek ~iv ~aad payload =
  match enc with
  | Some `A128CBC_HS256 ->
      (* RFC 7516 appendix B.1: first 128 bit hmac, last 128 bit aes *)
      let hmac_key, aes_key =
        U_String.split cek Mirage_crypto.AES.CBC.block_size
      in
      let key = Mirage_crypto.AES.CBC.of_secret aes_key in
      (* B.2 encryption in CBC mode *)
      Mirage_crypto.AES.CBC.encrypt ~key ~iv
        (Pkcs7.pad payload Mirage_crypto.AES.CBC.block_size)
      |> fun data ->
      (* B.5 input to HMAC computation *)
      let hmac_input =
        (* B.3 64 bit big-endian AAD length (in bits!) *)
        let aal = Bytes.create 8 in
        Bytes.set_int64_be aal 0 Int64.(mul 8L (of_int (String.length aad)));
        String.concat "" [ aad; iv; data; Bytes.unsafe_to_string aal ]
      in
      let computed_auth_tag =
        let full =
          Digestif.SHA256.hmac_string ~key:hmac_key hmac_input
          |> Digestif.SHA256.to_raw_string
        in
        (* B.7 truncate to 128 bit *)
        String.sub full 0 16
      in
      Ok (data, computed_auth_tag)
  | Some `A256GCM ->
      let module GCM = Mirage_crypto.AES.GCM in
      let key = GCM.of_secret cek in
      let adata = aad in
      GCM.authenticate_encrypt ~key ~nonce:iv ~adata payload |> fun cdata ->
      let cipher, tag_data =
        U_String.split cdata (String.length cdata - GCM.tag_size)
      in
      Ok (cipher, tag_data)
  | None -> Error `Missing_enc
  | _ -> Error `Unsupported_enc

let encrypt_cek (type a) alg (cek : string) ~(jwk : a Jwk.t) =
  let key =
    match jwk with
    | Rsa_priv rsa -> Ok (Mirage_crypto_pk.Rsa.pub_of_priv rsa.key)
    | Rsa_pub rsa -> Ok rsa.key
    | Oct _ -> Error `Unsupported_kty
    | Es256_priv _ -> Error `Unsupported_kty
    | Es256_pub _ -> Error `Unsupported_kty
    | Es384_priv _ -> Error `Unsupported_kty
    | Es384_pub _ -> Error `Unsupported_kty
    | Es512_priv _ -> Error `Unsupported_kty
    | Es512_pub _ -> Error `Unsupported_kty
    | Ed25519_priv _ -> Error `Unsupported_kty
    | Ed25519_pub _ -> Error `Unsupported_kty
  in
  Result.bind key (fun key ->
      match alg with
      | `RSA1_5 ->
          let ecek = Mirage_crypto_pk.Rsa.PKCS1.encrypt ~key cek in
          Ok ecek
      | `RSA_OAEP ->
          let jek = RSA_OAEP.encrypt ~key cek in
          Ok jek
      | _ -> Error `Invalid_alg)

let encrypt (type a) ~(jwk : a Jwk.t) t =
  let header_string = Header.to_string t.header in
  let ecek =
    encrypt_cek t.header.alg t.cek ~jwk |> Result.map U_Base64.url_encode_string
  in
  Result.bind ecek (fun ecek ->
      let eiv = U_Base64.url_encode_string t.iv in
      let ciphertext =
        encrypt_payload ?enc:t.header.enc ~cek:t.cek ~iv:t.iv ~aad:header_string
          t.payload
      in
      Result.bind ciphertext (fun (ciphertext, auth_tag) ->
          Ok
            (String.concat "."
               [
                 header_string;
                 ecek;
                 eiv;
                 U_Base64.url_encode_string ciphertext;
                 U_Base64.url_encode_string auth_tag;
               ])))

let decrypt_cek alg str ~(jwk : Jwk.priv Jwk.t) =
  let of_opt_string = function
    | Some c -> Ok c
    | None -> Error `Decrypt_cek_failed
  in
  match (alg, jwk) with
  | `RSA1_5, Jwk.Rsa_priv rsa ->
      let decoded =
        Utils.U_Base64.url_decode str
        |> Result.map (Mirage_crypto_pk.Rsa.PKCS1.decrypt ~key:rsa.key)
      in
      Result.bind decoded of_opt_string
  | `RSA_OAEP, Jwk.Rsa_priv rsa ->
      let decoded =
        Utils.U_Base64.url_decode str
        |> Result.map (RSA_OAEP.decrypt ~key:rsa.key)
      in
      Result.bind decoded of_opt_string
  | _ -> Error `Invalid_JWK

(* Move to Jwa? *)
let decrypt_ciphertext enc ~cek ~iv ~auth_tag ~aad ciphertext =
  let encrypted = U_Base64.url_decode ciphertext in
  Result.bind encrypted (fun encrypted ->
      match enc with
      | Some `A128CBC_HS256 ->
          (* RFC 7516 appendix B.1: first 128 bit hmac, last 128 bit aes *)
          let hmac_key, aes_key = U_String.split cek 16 in
          let key = Mirage_crypto.AES.CBC.of_secret aes_key in

          (* B.5 input to HMAC computation *)
          let hmac_input =
            (* B.3 64 bit big-endian AAD length (in bits!) *)
            let aal = Bytes.create 8 in
            Bytes.set_int64_be aal 0 Int64.(mul 8L (of_int (String.length aad)));
            String.concat "" [ aad; iv; encrypted; Bytes.unsafe_to_string aal ]
          in
          let computed_auth_tag =
            let full = Digestif.SHA256.hmac_string ~key:hmac_key hmac_input in
            (* B.7 truncate to 128 bit *)
            String.sub (Digestif.SHA256.to_raw_string full) 0 16
          in
          if not (String.equal computed_auth_tag auth_tag) then
            Error (`Msg "invalid auth tag")
          else
            (* B.2 encryption in CBC mode *)
            Mirage_crypto.AES.CBC.decrypt ~key ~iv encrypted |> Pkcs7.unpad
      | Some `A256GCM ->
          let module GCM = Mirage_crypto.AES.GCM in
          let key = GCM.of_secret cek in
          let adata = aad in
          let encrypted = encrypted ^ auth_tag in
          Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce:iv ~adata
            encrypted
          |> fun message ->
          message
          |> Option.map (fun x -> Ok x)
          |> Option.value ~default:(Error (`Msg "invalid auth tag"))
      | _ -> Error (`Msg "unsupported encryption"))

let decrypt ~(jwk : Jwk.priv Jwk.t) jwe =
  String.split_on_char '.' jwe |> function
  | [ enc_header; enc_cek; enc_iv; ciphertext; auth_tag ] ->
      let header = Header.of_string enc_header in
      Result.bind header (fun header ->
          let cek = decrypt_cek header.Header.alg ~jwk enc_cek in
          Result.bind cek (fun cek ->
              let iv = U_Base64.url_decode enc_iv in
              Result.bind iv (fun iv ->
                  let auth_tag = U_Base64.url_decode auth_tag in
                  Result.bind auth_tag (fun auth_tag ->
                      let payload =
                        decrypt_ciphertext header.Header.enc ~cek ~iv ~auth_tag
                          ~aad:enc_header ciphertext
                      in
                      Result.bind payload (fun payload ->
                          Ok { header; cek; iv; payload; aad = None })))))
  | _ -> Error `Invalid_JWE
