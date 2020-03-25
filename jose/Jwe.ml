(** {{: https://tools.ietf.org/html/rfc7516 } Link to RFC } *)

type aad
(** Additional Authentication Data *)

type protected
(** JWE Protected Header *)

type t = { header : Header.t; payload : string; aad : aad option }
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

let make_cek enc =
  let key_length = Jwa.enc_to_length enc in
  Mirage_crypto_rng.generate (key_length / 8)
  |> Cstruct.to_string |> Jwk.make_oct ~use:"enc"

let sign ~jwk ?protected cleartext =
  let () = match protected with Some _ -> () | None -> () in
  let _input_key =
    match jwk with
    | `A128CBC_HS256 -> Ok (Mirage_crypto_rng.generate 32)
    | `A256CBC_HS512 -> Ok (Mirage_crypto_rng.generate 64)
    | _ -> Error `Unsupported_enc
  in
  cleartext
