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
  match header.enc with
  | Some enc -> Ok (Mirage_crypto_rng.generate @@ Jwa.enc_to_iv_length enc)
  | None -> Error `Missing_enc

let make ~header payload =
  let cek =
    match header.Header.alg with
    | `Dir | `ECDH_ES -> Ok ""
    | _ -> make_cek header
  in
  Result.bind cek (fun cek ->
      let iv = make_iv header in
      Result.bind iv (fun iv ->
          let aad = None in
          Ok { header; cek; iv; aad; payload }))

let encrypt_payload ?enc ~cek ~iv ~aad payload =
  match enc with
  | Some `A128CBC_HS256 ->
      if Jwa.enc_to_length `A128CBC_HS256 <> String.length cek * 8 then
        Error `Invalid_JWK
      else
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
  | Some `A256CBC_HS512 ->
      if Jwa.enc_to_length `A256CBC_HS512 <> String.length cek * 8 then
        Error `Invalid_JWK
      else
        (* RFC 7518 section 5.2.5 / 5.2.2.1: first 256 bit hmac, last 256 bit aes *)
        let hmac_key, aes_key = U_String.split cek 32 in
        let key = Mirage_crypto.AES.CBC.of_secret aes_key in
        (* RFC 7518 section 5.2.2.1 step 3: encryption in CBC mode *)
        Mirage_crypto.AES.CBC.encrypt ~key ~iv
          (Pkcs7.pad payload Mirage_crypto.AES.CBC.block_size)
        |> fun data ->
        (* RFC 7518 section 5.2.2.1 step 5 / RFC 7516 appendix B.5: input to HMAC computation *)
        let hmac_input =
          (* RFC 7518 section 5.2.2.1 step 4: 64 bit big-endian AAD length (in bits!) *)
          let aal = Bytes.create 8 in
          Bytes.set_int64_be aal 0 Int64.(mul 8L (of_int (String.length aad)));
          String.concat "" [ aad; iv; data; Bytes.unsafe_to_string aal ]
        in
        let computed_auth_tag =
          let full =
            Digestif.SHA512.hmac_string ~key:hmac_key hmac_input
            |> Digestif.SHA512.to_raw_string
          in
          (* RFC 7518 section 5.2.5: truncate to 256 bit (32 octets) *)
          String.sub full 0 32
        in
        Ok (data, computed_auth_tag)
  | Some (`A128GCM | `A256GCM) ->
      if Jwa.enc_to_length (Option.get enc) <> String.length cek * 8 then
        Error `Invalid_JWK
      else
        (* RFC 7518 §5.3: AES GCM authenticated encryption with 96-bit IV and 128-bit tag *)
        let module GCM = Mirage_crypto.AES.GCM in
        let key = GCM.of_secret cek in
        let adata = aad in
        GCM.authenticate_encrypt ~key ~nonce:iv ~adata payload |> fun cdata ->
        let cipher, tag_data =
          U_String.split cdata (String.length cdata - GCM.tag_size)
        in
        Ok (cipher, tag_data)
  | None -> Error `Missing_enc
(* | _ -> Error `Unsupported_enc *)

type encrypt_key = Rsa of Mirage_crypto_pk.Rsa.pub | Oct of string

let encrypt_cek (type a) alg (cek : string) ~(jwk : a Jwk.t) =
  let key =
    match jwk with
    | Rsa_priv rsa -> Ok (Rsa (Mirage_crypto_pk.Rsa.pub_of_priv rsa.key))
    | Rsa_pub rsa -> Ok (Rsa rsa.key)
    | Oct oct when oct.use = None || oct.use = Some `Enc -> Ok (Oct oct.key)
    | Oct _ -> Error `Invalid_JWK
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
      match (key, alg) with
      | Rsa key, `RSA1_5 ->
          (* RFC 7518 §4.2: Key Encryption with RSAES-PKCS1-v1_5 *)
          let ecek = Mirage_crypto_pk.Rsa.PKCS1.encrypt ~key cek in
          Ok ecek
      | Rsa key, `RSA_OAEP ->
          (* RFC 7518 §4.3: Key Encryption with RSAES OAEP *)
          let jek = RSA_OAEP.encrypt ~key cek in
          Ok jek
      | Oct key, (`A128KW | `A256KW) ->
          (* RFC 7518 §4.4 & RFC 3394: Key Encryption with AES Key Wrap *)
          let kek =
            U_Base64.url_decode key |> Result.map_error (fun _ -> `Invalid_JWK)
          in
          Result.bind kek (fun kek ->
              let expected_len = if alg = `A128KW then 16 else 32 in
              if String.length kek <> expected_len then Error `Invalid_JWK
              else Aes_kw.wrap ~kek cek)
      | _ -> Error `Invalid_alg)

let negotiate_ke (type a) (jwk : a Jwk.t) =
  match jwk with
  | Jwk.Es256_pub jwk ->
      let epk_secret, epk_pub = Mirage_crypto_ec.P256.Dh.gen_key () in
      let epk_jwk =
        Mirage_crypto_ec.P256.Dsa.pub_of_octets epk_pub
        |> Result.map Jwk.make_pub_es256
      in
      let pub_octets = Mirage_crypto_ec.P256.Dsa.pub_to_octets jwk.key in
      let z = Mirage_crypto_ec.P256.Dh.key_exchange epk_secret pub_octets in
      Result.bind z (fun z -> Result.map (fun epk_jwk -> (z, epk_jwk)) epk_jwk)
      |> Result.map_error (fun _ -> `Msg "failed to negotiate key exchange")
  | Jwk.Es384_pub jwk ->
      let epk_secret, epk_pub = Mirage_crypto_ec.P384.Dh.gen_key () in
      let epk_jwk =
        Mirage_crypto_ec.P384.Dsa.pub_of_octets epk_pub
        |> Result.map Jwk.make_pub_es384
      in
      let pub_octets = Mirage_crypto_ec.P384.Dsa.pub_to_octets jwk.key in
      let z = Mirage_crypto_ec.P384.Dh.key_exchange epk_secret pub_octets in
      Result.bind z (fun z -> Result.map (fun epk_jwk -> (z, epk_jwk)) epk_jwk)
      |> Result.map_error (fun _ -> `Msg "failed to negotiate key exchange")
  | Jwk.Es512_pub jwk ->
      let epk_secret, epk_pub = Mirage_crypto_ec.P521.Dh.gen_key () in
      let epk_jwk =
        Mirage_crypto_ec.P521.Dsa.pub_of_octets epk_pub
        |> Result.map Jwk.make_pub_es512
      in
      let pub_octets = Mirage_crypto_ec.P521.Dsa.pub_to_octets jwk.key in
      let z = Mirage_crypto_ec.P521.Dh.key_exchange epk_secret pub_octets in
      Result.bind z (fun z -> Result.map (fun epk_jwk -> (z, epk_jwk)) epk_jwk)
      |> Result.map_error (fun _ -> `Msg "failed to negotiate key exchange")
  | Jwk.Es256_priv priv_jwk ->
      let epk_secret, epk_pub = Mirage_crypto_ec.P256.Dh.gen_key () in
      let epk_jwk =
        Mirage_crypto_ec.P256.Dsa.pub_of_octets epk_pub
        |> Result.map Jwk.make_pub_es256
      in
      let pub_key = Mirage_crypto_ec.P256.Dsa.pub_of_priv priv_jwk.key in
      let pub_octets = Mirage_crypto_ec.P256.Dsa.pub_to_octets pub_key in
      let z = Mirage_crypto_ec.P256.Dh.key_exchange epk_secret pub_octets in
      Result.bind z (fun z -> Result.map (fun epk_jwk -> (z, epk_jwk)) epk_jwk)
      |> Result.map_error (fun _ -> `Msg "failed to negotiate key exchange")
  | Jwk.Es384_priv priv_jwk ->
      let epk_secret, epk_pub = Mirage_crypto_ec.P384.Dh.gen_key () in
      let epk_jwk =
        Mirage_crypto_ec.P384.Dsa.pub_of_octets epk_pub
        |> Result.map Jwk.make_pub_es384
      in
      let pub_key = Mirage_crypto_ec.P384.Dsa.pub_of_priv priv_jwk.key in
      let pub_octets = Mirage_crypto_ec.P384.Dsa.pub_to_octets pub_key in
      let z = Mirage_crypto_ec.P384.Dh.key_exchange epk_secret pub_octets in
      Result.bind z (fun z -> Result.map (fun epk_jwk -> (z, epk_jwk)) epk_jwk)
      |> Result.map_error (fun _ -> `Msg "failed to negotiate key exchange")
  | Jwk.Es512_priv priv_jwk ->
      let epk_secret, epk_pub = Mirage_crypto_ec.P521.Dh.gen_key () in
      let epk_jwk =
        Mirage_crypto_ec.P521.Dsa.pub_of_octets epk_pub
        |> Result.map Jwk.make_pub_es512
      in
      let pub_key = Mirage_crypto_ec.P521.Dsa.pub_of_priv priv_jwk.key in
      let pub_octets = Mirage_crypto_ec.P521.Dsa.pub_to_octets pub_key in
      let z = Mirage_crypto_ec.P521.Dh.key_exchange epk_secret pub_octets in
      Result.bind z (fun z -> Result.map (fun epk_jwk -> (z, epk_jwk)) epk_jwk)
      |> Result.map_error (fun _ -> `Msg "failed to negotiate key exchange")
  | _ -> Error `Invalid_JWK

let encrypt (type a) ~(jwk : a Jwk.t) t =
  match t.header.alg with
  | `RSA_OAEP | `RSA1_5 | `A128KW | `A256KW ->
      let header_string = Header.to_string t.header in
      let ecek =
        encrypt_cek t.header.alg t.cek ~jwk
        |> Result.map U_Base64.url_encode_string
      in
      Result.bind ecek (fun ecek ->
          let eiv = U_Base64.url_encode_string t.iv in
          let ciphertext =
            encrypt_payload ?enc:t.header.enc ~cek:t.cek ~iv:t.iv
              ~aad:header_string t.payload
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
  | `Dir -> (
      match jwk with
      | Jwk.Oct jwk when jwk.Jwk.use = Some `Enc || jwk.use = None ->
          let header_string = Header.to_string t.header in
          let ecek = "" in
          let eiv = U_Base64.url_encode_string t.iv in
          let cekr =
            U_Base64.url_decode jwk.key
            |> Result.map_error (fun _ -> `Invalid_JWK)
          in
          let ciphertext =
            Result.bind cekr (fun cek ->
                encrypt_payload ?enc:t.header.enc ~cek ~iv:t.iv
                  ~aad:header_string t.payload)
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
                   ]))
      | _ -> Error `Invalid_JWK)
  | `ECDH_ES | `ECDH_ES_A128KW ->
      let ecdh = negotiate_ke jwk in
      Result.bind ecdh (fun (z, epk) ->
          let header = { t.header with epk = Some epk } in
          let header_string = Header.to_string header in

          match (header.alg, header.enc) with
          | `ECDH_ES, Some enc ->
              let keydatalen = Jwa.enc_to_length enc in
              let alg_id = Jwa.enc_to_string enc in
              let cek =
                Utils.Concat_kdf.derive ~z ~keydatalen ~alg_id ?apu:header.apu
                  ?apv:header.apv ()
              in
              let ecek = "" in
              let eiv = U_Base64.url_encode_string t.iv in
              let ciphertext =
                encrypt_payload ~enc ~cek ~iv:t.iv ~aad:header_string t.payload
              in
              Result.map
                (fun (ciphertext, auth_tag) ->
                  String.concat "."
                    [
                      header_string;
                      ecek;
                      eiv;
                      U_Base64.url_encode_string ciphertext;
                      U_Base64.url_encode_string auth_tag;
                    ])
                ciphertext
          | `ECDH_ES_A128KW, Some enc ->
              let keydatalen = 128 in
              let alg_id = Jwa.alg_to_string `ECDH_ES_A128KW in
              let kek =
                Utils.Concat_kdf.derive ~z ~keydatalen ~alg_id ?apu:header.apu
                  ?apv:header.apv ()
              in
              let ecek =
                Aes_kw.wrap ~kek t.cek |> Result.map U_Base64.url_encode_string
              in
              Result.bind ecek (fun ecek ->
                  let eiv = U_Base64.url_encode_string t.iv in
                  let ciphertext =
                    encrypt_payload ~enc ~cek:t.cek ~iv:t.iv ~aad:header_string
                      t.payload
                  in
                  Result.map
                    (fun (ciphertext, auth_tag) ->
                      String.concat "."
                        [
                          header_string;
                          ecek;
                          eiv;
                          U_Base64.url_encode_string ciphertext;
                          U_Base64.url_encode_string auth_tag;
                        ])
                    ciphertext)
          | _, None -> Error `Missing_enc
          | _, Some _ -> Error `Invalid_alg)
  | _ -> Error `Invalid_alg

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
  | (`A128KW | `A256KW), Jwk.Oct oct when oct.use = None || oct.use = Some `Enc
    ->
      let kek =
        U_Base64.url_decode oct.key |> Result.map_error (fun _ -> `Invalid_JWK)
      in
      Result.bind kek (fun kek ->
          let expected_len = if alg = `A128KW then 16 else 32 in
          if String.length kek <> expected_len then Error `Invalid_JWK
          else Result.bind (Utils.U_Base64.url_decode str) (Aes_kw.unwrap ~kek))
  | _ -> Error `Invalid_JWK

(* Move to Jwa? *)
let decrypt_ciphertext enc ~cek ~iv ~auth_tag ~aad ciphertext =
  let encrypted = U_Base64.url_decode ciphertext in
  Result.bind encrypted (fun encrypted ->
      match enc with
      | Some `A128CBC_HS256 ->
          if Jwa.enc_to_length `A128CBC_HS256 <> String.length cek * 8 then
            Error `Invalid_JWK
          else
            (* RFC 7516 appendix B.1: first 128 bit hmac, last 128 bit aes *)
            let hmac_key, aes_key = U_String.split cek 16 in
            let key = Mirage_crypto.AES.CBC.of_secret aes_key in

            (* B.5 input to HMAC computation *)
            let hmac_input =
              (* B.3 64 bit big-endian AAD length (in bits!) *)
              let aal = Bytes.create 8 in
              Bytes.set_int64_be aal 0
                Int64.(mul 8L (of_int (String.length aad)));
              String.concat ""
                [ aad; iv; encrypted; Bytes.unsafe_to_string aal ]
            in
            let computed_auth_tag =
              let full = Digestif.SHA256.hmac_string ~key:hmac_key hmac_input in
              (* B.7 truncate to 128 bit *)
              String.sub (Digestif.SHA256.to_raw_string full) 0 16
            in
            if not (Eqaf.equal computed_auth_tag auth_tag) then
              Error `Invalid_auth_tag
            else
              (* B.2 encryption in CBC mode *)
              Mirage_crypto.AES.CBC.decrypt ~key ~iv encrypted |> Pkcs7.unpad
      | Some `A256CBC_HS512 ->
          if Jwa.enc_to_length `A256CBC_HS512 <> String.length cek * 8 then
            Error `Invalid_JWK
          else
            (* RFC 7518 section 5.2.5 / 5.2.2.1: first 256 bit hmac, last 256 bit aes *)
            let hmac_key, aes_key = U_String.split cek 32 in
            let key = Mirage_crypto.AES.CBC.of_secret aes_key in

            (* RFC 7518 section 5.2.2.1 step 5 / RFC 7516 appendix B.5: input to HMAC computation *)
            let hmac_input =
              (* RFC 7518 section 5.2.2.1 step 4: 64 bit big-endian AAD length (in bits!) *)
              let aal = Bytes.create 8 in
              Bytes.set_int64_be aal 0
                Int64.(mul 8L (of_int (String.length aad)));
              String.concat ""
                [ aad; iv; encrypted; Bytes.unsafe_to_string aal ]
            in
            let computed_auth_tag =
              let full = Digestif.SHA512.hmac_string ~key:hmac_key hmac_input in
              (* RFC 7518 section 5.2.5: truncate to 256 bit (32 octets) *)
              String.sub (Digestif.SHA512.to_raw_string full) 0 32
            in
            if not (Eqaf.equal computed_auth_tag auth_tag) then
              Error `Invalid_auth_tag
            else
              (* RFC 7518 section 5.2.2.2 step 3: decryption in CBC mode *)
              Mirage_crypto.AES.CBC.decrypt ~key ~iv encrypted |> Pkcs7.unpad
      | Some (`A256GCM | `A128GCM) ->
          if Jwa.enc_to_length (Option.get enc) <> String.length cek * 8 then
            Error `Invalid_JWK
          else
            let module GCM = Mirage_crypto.AES.GCM in
            let key = GCM.of_secret cek in
            let adata = aad in
            let encrypted = encrypted ^ auth_tag in
            Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce:iv ~adata
              encrypted
            |> fun message ->
            message
            |> Option.map (fun x -> Ok x)
            |> Option.value ~default:(Error `Invalid_auth_tag)
      | _ -> Error `Unsupported_enc)

let compute_shared_secret ~jwk ~epk =
  match (jwk, epk) with
  | Jwk.Es256_priv jwk, Jwk.Es256_pub epk ->
      let priv_octets = Mirage_crypto_ec.P256.Dsa.priv_to_octets jwk.key in
      let secret = Mirage_crypto_ec.P256.Dh.secret_of_octets priv_octets in
      let epk_pub_octets = Mirage_crypto_ec.P256.Dsa.pub_to_octets epk.key in
      Result.bind secret (fun (secret, _) ->
          Mirage_crypto_ec.P256.Dh.key_exchange secret epk_pub_octets)
      |> Result.map_error (fun _ -> `Msg "failed to compute shared secret")
  | Jwk.Es384_priv jwk, Jwk.Es384_pub epk ->
      let priv_octets = Mirage_crypto_ec.P384.Dsa.priv_to_octets jwk.key in
      let secret = Mirage_crypto_ec.P384.Dh.secret_of_octets priv_octets in
      let epk_pub_octets = Mirage_crypto_ec.P384.Dsa.pub_to_octets epk.key in
      Result.bind secret (fun (secret, _) ->
          Mirage_crypto_ec.P384.Dh.key_exchange secret epk_pub_octets)
      |> Result.map_error (fun _ -> `Msg "failed to compute shared secret")
  | Jwk.Es512_priv jwk, Jwk.Es512_pub epk ->
      let priv_octets = Mirage_crypto_ec.P521.Dsa.priv_to_octets jwk.key in
      let secret = Mirage_crypto_ec.P521.Dh.secret_of_octets priv_octets in
      let epk_pub_octets = Mirage_crypto_ec.P521.Dsa.pub_to_octets epk.key in
      Result.bind secret (fun (secret, _) ->
          Mirage_crypto_ec.P521.Dh.key_exchange secret epk_pub_octets)
      |> Result.map_error (fun _ -> `Msg "failed to compute shared secret")
  | _ -> Error `Invalid_JWK

let decrypt ~(jwk : Jwk.priv Jwk.t) jwe =
  String.split_on_char '.' jwe |> function
  | [ enc_header; enc_cek; enc_iv; ciphertext; auth_tag ] ->
      let header = Header.of_string enc_header in
      Result.bind header (fun header ->
          match header.Header.alg with
          | `RSA_OAEP | `RSA1_5 | `A128KW | `A256KW ->
              let cek = decrypt_cek header.Header.alg ~jwk enc_cek in
              Result.bind cek (fun cek ->
                  let iv = U_Base64.url_decode enc_iv in
                  Result.bind iv (fun iv ->
                      let auth_tag = U_Base64.url_decode auth_tag in
                      Result.bind auth_tag (fun auth_tag ->
                          let payload =
                            decrypt_ciphertext header.Header.enc ~cek ~iv
                              ~auth_tag ~aad:enc_header ciphertext
                          in
                          Result.bind payload (fun payload ->
                              Ok { header; cek; iv; payload; aad = None }))))
          | `Dir when enc_cek <> "" -> Error `Invalid_JWE
          | `Dir -> (
              match jwk with
              | Jwk.Oct jwk when jwk.Jwk.use = Some `Enc || jwk.use = None ->
                  let cekr =
                    U_Base64.url_decode jwk.key
                    |> Result.map_error (fun _ -> `Invalid_JWK)
                  in
                  Result.bind cekr (fun cek ->
                      let iv = U_Base64.url_decode enc_iv in
                      Result.bind iv (fun iv ->
                          let auth_tag = U_Base64.url_decode auth_tag in
                          Result.bind auth_tag (fun auth_tag ->
                              let payload =
                                decrypt_ciphertext header.Header.enc ~cek ~iv
                                  ~auth_tag ~aad:enc_header ciphertext
                              in
                              Result.bind payload (fun payload ->
                                  Ok { header; cek; iv; payload; aad = None }))))
              | _ -> Error `Invalid_JWK)
          | `ECDH_ES -> (
              if enc_cek <> "" then Error `Invalid_JWE
              else
                match (header.epk, header.enc) with
                | None, _ -> Error `Missing_epk
                | _, None -> Error `Missing_enc
                | Some epk, Some enc ->
                    let z = compute_shared_secret ~jwk ~epk in
                    Result.bind z (fun z ->
                        let keydatalen = Jwa.enc_to_length enc in
                        let alg_id = Jwa.enc_to_string enc in
                        let cek =
                          Utils.Concat_kdf.derive ~z ~keydatalen ~alg_id
                            ?apu:header.apu ?apv:header.apv ()
                        in
                        let iv = U_Base64.url_decode enc_iv in
                        Result.bind iv (fun iv ->
                            let auth_tag = U_Base64.url_decode auth_tag in
                            Result.bind auth_tag (fun auth_tag ->
                                decrypt_ciphertext header.enc ~cek ~iv ~auth_tag
                                  ~aad:enc_header ciphertext
                                |> Result.map (fun payload ->
                                    { header; cek; iv; payload; aad = None }))))
              )
          | `ECDH_ES_A128KW -> (
              match (header.epk, header.enc) with
              | None, _ -> Error `Missing_epk
              | _, None -> Error `Missing_enc
              | Some epk, Some _enc ->
                  let z = compute_shared_secret ~jwk ~epk in
                  Result.bind z (fun z ->
                      let keydatalen = 128 in
                      let alg_id = Jwa.alg_to_string `ECDH_ES_A128KW in
                      let kek =
                        Utils.Concat_kdf.derive ~z ~keydatalen ~alg_id
                          ?apu:header.apu ?apv:header.apv ()
                      in
                      Result.bind (U_Base64.url_decode enc_cek)
                        (fun enc_cek_raw ->
                          let cek = Aes_kw.unwrap ~kek enc_cek_raw in
                          Result.bind cek (fun cek ->
                              let iv = U_Base64.url_decode enc_iv in
                              Result.bind iv (fun iv ->
                                  let auth_tag = U_Base64.url_decode auth_tag in
                                  Result.bind auth_tag (fun auth_tag ->
                                      decrypt_ciphertext header.enc ~cek ~iv
                                        ~auth_tag ~aad:enc_header ciphertext
                                      |> Result.map (fun payload ->
                                          {
                                            header;
                                            cek;
                                            iv;
                                            payload;
                                            aad = None;
                                          })))))))
          | _ -> Error `Unsupported_alg)
  | _ -> Error `Invalid_JWE
