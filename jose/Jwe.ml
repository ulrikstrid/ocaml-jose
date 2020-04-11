(** {{: https://tools.ietf.org/html/rfc7516 } Link to RFC } *)

type aad
(** Additional Authentication Data *)

type protected
(** JWE Protected Header *)

type t = {
  header : Header.t;
  cek : string;
  init_vector : string;
  payload : string;
  aad : aad option;
}
(**
JOSE header
.
JWE Encrypted Key
.
JWE initialization vector
.
JWE Additional Authentication Data (AAD)
.
JWE Ciphertext
.
JWE Authentication Tag
 *)

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

let encrypt ?protected payload ~(jwk : Jwk.priv Jwk.t) =
  let () = match protected with Some _ -> () | None -> () in
  let _input_key =
    match Jwk.get_alg jwk with
    | Jwa.RSA_OAEP -> Ok (Mirage_crypto_rng.generate 32)
    | _ -> Error `Unsupported_enc
  in
  payload

(**
JOSE header
.
JWE Encrypted Key
.
JWE initialization vector
.
JWE Additional Authentication Data (AAD)
.
JWE Ciphertext
.
JWE Authentication Tag
 *)

(*
Steps to 
*)

open Utils

let decrypt_cek alg str ~(jwk : Jwk.priv Jwk.t) =
  let of_opt_cstruct = function
    | Some c -> Ok (Cstruct.to_string c)
    | None -> Error `Decrypt_cek_failed
  in
  match alg, jwk with
  | Jwa.RSA1_5, Jwk.Rsa_priv rsa ->
    Utils.RBase64.url_decode str
    |> RResult.map Cstruct.of_string
    |> RResult.map (Mirage_crypto_pk.Rsa.PKCS1.decrypt ~key:rsa.key)
    |> RResult.flat_map of_opt_cstruct
  | _ -> Error `Invalid_JWK

let pkcs7_unpad cs =
  let cs_len = Cstruct.len cs in
  let pad_len = Cstruct.get_uint8 cs (cs_len - 1) in
  let data, padding = Cstruct.split cs (cs_len - pad_len) in
  let rec check idx =
    if idx >= pad_len then true else
      (Cstruct.get_uint8 padding idx = pad_len) && check (idx + 1)
  in
  if check 0 then Ok data else Error (`Msg "bad padding")

let bind v f = match v with Ok v -> f v | Error _ as e -> e

let (>>=) = bind

let decrypt_ciphertext enc ~cek ~init_vector ~auth_tag ~aad ciphertext =
  match enc with
  | Some Jwa.A128CBC_HS256 ->
    (* RFC 7516 appendix B.1: first 128 bit hmac, last 128 bit aes *)
    let hmac_key, aes_key = Cstruct.(split (of_string cek) 16) in
    let key = Mirage_crypto.Cipher_block.AES.CBC.of_secret aes_key in
    let iv = Cstruct.of_string init_vector in
    RBase64.url_decode ciphertext >>= fun encrypted ->
    let encrypted = Cstruct.of_string encrypted in
    (* B.5 input to HMAC computation *)
    let hmac_input =
      (* B.3 64 bit big-endian AAD length (in bits!) *)
      let aal = Cstruct.create 8 in
      Cstruct.BE.set_uint64 aal 0 Int64.(mul 8L (of_int (String.length aad)));
      Cstruct.(concat [ of_string aad ; iv ; encrypted ; aal ])
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
      |> pkcs7_unpad >>= fun data ->
      Ok (Cstruct.to_string data)
  | _ -> Error (`Msg "unsupported encryption")


let decrypt jwe ~(jwk : Jwk.priv Jwk.t) =
  String.split_on_char '.' jwe |> function
  | [ enc_header; enc_cek; enc_init_vector; ciphertext; auth_tag ] -> (
      Header.of_string enc_header >>= fun header ->
      decrypt_cek header.Header.alg ~jwk enc_cek >>= fun cek ->
      RBase64.url_decode enc_init_vector >>= fun init_vector ->
      RBase64.url_decode auth_tag >>= fun auth_tag ->
      decrypt_ciphertext header.Header.enc ~cek ~init_vector ~auth_tag ~aad:enc_header ciphertext >>= fun payload ->
      Ok { header; cek; init_vector = enc_init_vector; payload; aad = None })
  | _ -> Error `Invalid_JWE
