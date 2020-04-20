(** {{: https://tools.ietf.org/html/rfc7516 } Link to RFC } *)
open Utils

type t = {
  header : Header.t;
  cek : string;
  init_vector : string;
  payload : string;
  aad : string option;
}

module RSA_OAEP = Mirage_crypto_pk.Rsa.OAEP (Mirage_crypto.Hash.SHA1)

let bind v f = match v with Ok v -> f v | Error _ as e -> e

let ( >>= ) = bind

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

let make_cek enc =
  let key_length = Jwa.enc_to_length enc in
  Mirage_crypto_rng.generate (key_length / 8)
  |> Cstruct.to_string
  |> Jwk.make_oct ~use:`Enc

let pkcs7_pad data block_size =
  let pad_size = block_size - (Cstruct.len data mod block_size) in
  (* this is the remaining bytes in the last block *)
  let pad = Cstruct.create pad_size in
  Cstruct.memset pad pad_size;
  (* fills the pad buffer with bytes each containing "pad_size" as value *)
  Cstruct.append data pad

let encrypt_payload ?enc ~cek ~init_vector ~aad payload =
  let iv = Cstruct.of_string init_vector in
  match enc with
  | Some `A128CBC_HS256 ->
      (* RFC 7516 appendix B.1: first 128 bit hmac, last 128 bit aes *)
      let hmac_key, aes_key =
        Cstruct.(
          split (of_string cek) Mirage_crypto.Cipher_block.AES.CBC.block_size)
      in
      let key = Mirage_crypto.Cipher_block.AES.CBC.of_secret aes_key in
      (* B.2 encryption in CBC mode *)
      Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv
        (pkcs7_pad
           (Cstruct.of_string payload)
           Mirage_crypto.Cipher_block.AES.CBC.block_size)
      |> fun data ->
      (* B.5 input to HMAC computation *)
      let hmac_input =
        (* B.3 64 bit big-endian AAD length (in bits!) *)
        let aal = Cstruct.create 8 in
        Cstruct.BE.set_uint64 aal 0 Int64.(mul 8L (of_int (String.length aad)));
        Cstruct.(concat [ of_string aad; iv; data; aal ])
      in
      let computed_auth_tag =
        let full = Mirage_crypto.Hash.SHA256.hmac ~key:hmac_key hmac_input in
        (* B.7 truncate to 128 bit *)
        Cstruct.sub full 0 16 |> Cstruct.to_string
      in
      Ok (Cstruct.to_string data, computed_auth_tag)
  | Some `A256GCM ->
      let cek = Cstruct.of_string cek in
      let key = Mirage_crypto.Cipher_block.AES.GCM.of_secret cek in
      let adata = Cstruct.of_string aad in
      Mirage_crypto.Cipher_block.AES.GCM.encrypt ~key ~iv ~adata
        (Cstruct.of_string payload)
      |> fun { message; tag } ->
      let tag_string = Cstruct.to_string tag in
      let ciphertext = Cstruct.to_string message in
      Ok (ciphertext, tag_string)
  | _ -> Error (`Msg "unsupported encryption")

let encrypt_cek (type a) alg (cek : string) ~(jwk : a Jwk.t) =
  let key : Mirage_crypto_pk.Rsa.pub =
    match jwk with
    | Rsa_priv rsa -> Mirage_crypto_pk.Rsa.pub_of_priv rsa.key
    | Rsa_pub rsa -> rsa.key
    | Oct _ -> raise (Invalid_argument "oct")
  in
  match alg with
  | `RSA1_5 ->
      let ecek =
        cek |> Cstruct.of_string
        |> Mirage_crypto_pk.Rsa.PKCS1.encrypt ~key
        |> Cstruct.to_string
      in
      Ok ecek
  | `RSA_OAEP ->
      let cek = Cstruct.of_string cek in
      let jek = RSA_OAEP.encrypt ~key cek |> Cstruct.to_string in
      Ok jek
  | _ -> Error `Invalid_alg

let encrypt (type a) ~(jwk : a Jwk.t) t =
  let header_string = Header.to_string t.header |> RResult.get_exn in
  let ecek =
    encrypt_cek t.header.alg t.cek ~jwk
    |> RResult.get_exn |> RBase64.url_encode_string
  in
  let einit_vector = RBase64.url_encode_string t.init_vector in
  let ciphertext, auth_tag =
    encrypt_payload ?enc:t.header.enc ~cek:t.cek ~init_vector:t.init_vector
      ~aad:header_string t.payload
    |> RResult.get_exn
  in
  String.concat "."
    [
      header_string;
      ecek;
      einit_vector;
      RBase64.url_encode_string ciphertext;
      RBase64.url_encode_string auth_tag;
    ]

let decrypt_cek alg str ~(jwk : Jwk.priv Jwk.t) =
  let of_opt_cstruct = function
    | Some c -> Ok (Cstruct.to_string c)
    | None -> Error `Decrypt_cek_failed
  in
  match (alg, jwk) with
  | `RSA1_5, Jwk.Rsa_priv rsa ->
      Utils.RBase64.url_decode str
      |> RResult.map Cstruct.of_string
      |> RResult.map (Mirage_crypto_pk.Rsa.PKCS1.decrypt ~key:rsa.key)
      |> RResult.flat_map of_opt_cstruct
  | `RSA_OAEP, Jwk.Rsa_priv rsa ->
      Utils.RBase64.url_decode str
      |> RResult.map Cstruct.of_string
      |> RResult.map (RSA_OAEP.decrypt ~key:rsa.key)
      |> RResult.flat_map of_opt_cstruct
  | _ -> Error `Invalid_JWK

let pkcs7_unpad cs =
  let cs_len = Cstruct.len cs in
  let pad_len = Cstruct.get_uint8 cs (cs_len - 1) in
  let data, padding = Cstruct.split cs (cs_len - pad_len) in
  let rec check idx =
    if idx >= pad_len then true
    else Cstruct.get_uint8 padding idx = pad_len && check (idx + 1)
  in
  if check 0 then Ok data else Error (`Msg "bad padding")

(* Move to Jwa? *)
let decrypt_ciphertext enc ~cek ~init_vector ~auth_tag ~aad ciphertext =
  let iv = Cstruct.of_string init_vector in
  RBase64.url_decode ciphertext >>= fun encrypted ->
  let encrypted = Cstruct.of_string encrypted in
  match enc with
  | Some `A128CBC_HS256 ->
      (* RFC 7516 appendix B.1: first 128 bit hmac, last 128 bit aes *)
      let hmac_key, aes_key = Cstruct.(split (of_string cek) 16) in
      let key = Mirage_crypto.Cipher_block.AES.CBC.of_secret aes_key in

      (* B.5 input to HMAC computation *)
      let hmac_input =
        (* B.3 64 bit big-endian AAD length (in bits!) *)
        let aal = Cstruct.create 8 in
        Cstruct.BE.set_uint64 aal 0 Int64.(mul 8L (of_int (String.length aad)));
        Cstruct.(concat [ of_string aad; iv; encrypted; aal ])
      in
      let computed_auth_tag =
        let full = Mirage_crypto.Hash.SHA256.hmac ~key:hmac_key hmac_input in
        (* B.7 truncate to 128 bit *)
        Cstruct.sub full 0 16 |> Cstruct.to_string
      in
      if not (String.equal computed_auth_tag auth_tag) then
        Error (`Msg "invalid auth tag")
      else
        (* B.2 encryption in CBC mode *)
        Mirage_crypto.Cipher_block.AES.CBC.decrypt ~key ~iv encrypted
        |> pkcs7_unpad
        >>= fun data -> Ok (Cstruct.to_string data)
  | Some `A256GCM ->
      let cek = Cstruct.of_string cek in
      let key = Mirage_crypto.Cipher_block.AES.GCM.of_secret cek in
      let adata = Cstruct.of_string aad in
      Mirage_crypto.Cipher_block.AES.GCM.decrypt ~key ~iv ~adata encrypted
      |> fun { message; tag } ->
      let tag_string = Cstruct.to_string tag in
      if tag_string = auth_tag then Ok (Cstruct.to_string message)
      else Error (`Msg "invalid auth tag")
  | _ -> Error (`Msg "unsupported encryption")

let decrypt jwe ~(jwk : Jwk.priv Jwk.t) =
  String.split_on_char '.' jwe |> function
  | [ enc_header; enc_cek; enc_init_vector; ciphertext; auth_tag ] ->
      Header.of_string enc_header >>= fun header ->
      decrypt_cek header.Header.alg ~jwk enc_cek >>= fun cek ->
      RBase64.url_decode enc_init_vector >>= fun init_vector ->
      RBase64.url_decode auth_tag >>= fun auth_tag ->
      decrypt_ciphertext header.Header.enc ~cek ~init_vector ~auth_tag
        ~aad:enc_header ciphertext
      >>= fun payload -> Ok { header; cek; init_vector; payload; aad = None }
  | _ -> Error `Invalid_JWE
