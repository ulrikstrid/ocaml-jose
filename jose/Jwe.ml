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

let decrypt_cek str ~(jwk : Jwk.priv Jwk.t) =
  let of_opt_cstruct = function
    | Some c -> Ok (Cstruct.to_string c)
    | None -> Error `Decrypt_cek_failed
  in
  match jwk with
  | Jwk.Rsa_priv rsa ->
      Utils.RBase64.url_decode str
      |> RResult.map Cstruct.of_string
      |> RResult.map (Mirage_crypto_pk.Rsa.PKCS1.decrypt ~key:rsa.key)
      |> RResult.flat_map of_opt_cstruct
  | _ -> Error `Invalid_JWK

let decrypt_ciphertext ~cek ~init_vector ciphertext =
  let key =
    Cstruct.of_string cek |> Mirage_crypto.Cipher_block.AES.CBC.of_secret
  in
  let iv = Cstruct.of_string init_vector in
  RBase64.url_decode ciphertext
  |> RResult.map Cstruct.of_string
  |> RResult.map (Mirage_crypto.Cipher_block.AES.CBC.decrypt ~key ~iv)
  |> RResult.map Cstruct.to_string

let decrypt jwe ~(jwk : Jwk.priv Jwk.t) =
  String.split_on_char '.' jwe |> function
  | [ header; enc_cek; enc_init_vector; ciphertext; _auth_tag ] -> (
      let header_r = Header.of_string header in
      let cek_r = decrypt_cek ~jwk enc_cek in
      let payload_r =
        RResult.flat_map
          (fun init_vector ->
            RResult.flat_map
              (fun cek -> decrypt_ciphertext ~cek ~init_vector ciphertext)
              cek_r)
          (RBase64.url_decode enc_init_vector)
      in
      match (header_r, cek_r, payload_r) with
      | Ok header, Ok cek, Ok payload ->
          Ok { header; cek; init_vector = enc_init_vector; payload; aad = None }
      | _ -> Error `Invalid_JWE )
  | _ -> Error `Invalid_JWE
