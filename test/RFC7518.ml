(* Tests for RFC 7518 (JSON Web Algorithms) *)
let () = Mirage_crypto_rng_unix.use_default ()
let rsa_priv = Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
let rsa_pub = Jose.Jwk.pub_of_priv rsa_priv

let rsa_priv_jwk =
  Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string |> CCResult.get_exn

open Helpers

let frodo_payload =
  "You can trust us to stick with you through thick and thin\xe2\x80\x93to the \
   bitter end. And you can trust us to keep any secret of \
   yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us \
   to let you face trouble alone, and go off without a word. We are your \
   friends, Frodo."

(* RFC 7520 5.6: Direct Encryption Using AES-GCM (A128GCM + dir) *)
let rfc7520_oct_128gcm_key =
  {|{"kty":"oct",
     "kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a",
     "use":"enc",
     "alg":"A128GCM",
     "k":"XctOhJAkA-pD9Lh7ZgW_2A"}|}

let rfc7520_5_6_jwe =
  "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0."
  ^ "." ^ "refa467QzzKx6QAB."
  ^ "JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp."
  ^ "vbb32Xvllea2OtmHAdccRQ"

(* RFC 7516 A.3: AES Key Wrap (A128KW) and AES_128_CBC_HMAC_SHA_256 *)
let rfc7516_a3_oct_key = {|{"kty":"oct",
     "k":"GawgguFyGrWKav7AX4VKUg"}|}

let rfc7516_a3_jwe =
  "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
  ^ "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
  ^ "AxY8DCtDaGlsbGljb3RoZQ." ^ "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
  ^ "U0m_YmjN04DJvceFICbCVQ"

(* RFC 7520 5.8: AES Key Wrap (A128KW) with AES-GCM (A128GCM) *)
let rfc7520_5_8_oct_key =
  {|{"kty":"oct",
     "kid":"81b20965-8332-43d9-a468-82160ad91ac8",
     "use":"enc",
     "alg":"A128KW",
     "k":"GZy6sIZ6wl9NJOKB-jnmVQ"}|}

let rfc7520_5_8_jwe =
  "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0."
  ^ "CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx." ^ "Qx0pmsDa8KnJc9Jo."
  ^ "AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF."
  ^ "ER7MWJZ1FBI_NKvn7Zb1Lw"

(* RFC 7520 5.5: ECDH-ES with AES-CBC-HMAC-SHA2 (A128CBC-HS256) *)
let rfc7520_5_5_ec_priv =
  {|{"kty":"EC",
     "kid":"meriadoc.brandybuck@buckland.example",
     "use":"enc",
     "crv":"P-256",
     "x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
     "y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
     "d":"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"}|}

let rfc7520_5_5_jwe =
  "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidWNrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZFlvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ."
  ^ "." ^ "yc9N8v5sYyv3iGQT926IUg."
  ^ "BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ6195_JGG2m9Csg."
  ^ "WCCkNa-x4BeB9hIDIfFuhg"

(* RFC 7520 5.4: ECDH-ES+A128KW with AES-GCM (A128GCM) *)
let rfc7520_5_4_ec_priv =
  {|{"kty":"EC",
     "kid":"peregrin.took@tuckborough.example",
     "use":"enc",
     "crv":"P-384",
     "x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2",
     "y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP",
     "d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"}|}

let rfc7520_5_4_jwe =
  "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0."
  ^ "0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2." ^ "mH-G2zVqgztUtnW_."
  ^ "tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ."
  ^ "WuGzxmcreYjpHGJoa17EBg"

let jwa_tests =
  ( "RFC7518",
    [
      Alcotest.test_case "3.1: ES256 (Recommended+) signing and validation"
        `Quick (fun () ->
          let es256_priv =
            Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn
          in
          let es256_pub = Jose.Jwk.pub_of_priv es256_priv in
          let header = Jose.Header.make_header ~alg:`ES256 es256_priv in
          let payload = "hello ES256 RFC 7518" in
          let jws =
            Jose.Jws.sign ~header ~payload es256_priv |> CCResult.get_exn
          in
          let validated = Jose.Jws.validate ~jwk:es256_pub jws in
          Alcotest.(check bool)
            "ES256 signature validates with public key" true
            (CCResult.is_ok validated);
          let tampered_jws = { jws with payload = "tampered payload" } in
          let res_tampered = Jose.Jws.validate ~jwk:es256_pub tampered_jws in
          Alcotest.(check bool)
            "ES256 validation fails on tampered payload" true
            (CCResult.is_error res_tampered));
      Alcotest.test_case "4.1: RSA-OAEP-256 key management support in JWE"
        `Quick (fun () ->
          let header_json =
            `Assoc
              [ ("alg", `String "RSA-OAEP-256"); ("enc", `String "A256GCM") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe_res = Jose.Jwe.make ~header "secret payload" in
          Alcotest.(check bool)
            "Jwe.make succeeds with RSA-OAEP-256" true (CCResult.is_ok jwe_res));
      Alcotest.test_case "5.3: A256GCM IV length is 96 bits (12 bytes)" `Quick
        (fun () ->
          let header =
            Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A256GCM rsa_priv_jwk
          in
          let jwe =
            Jose.Jwe.make ~header "secret message" |> CCResult.get_exn
          in
          Alcotest.(check int)
            "A256GCM IV length must be 12 bytes (96 bits)" 12
            (String.length jwe.iv));
      Alcotest.test_case
        "5.1 / 5.2.5: A256CBC-HS512 header parsing, CEK (64 bytes), IV (16 \
         bytes), and JWE RSA-OAEP roundtrip"
        `Quick (fun () ->
          let header_json =
            `Assoc
              [ ("alg", `String "RSA-OAEP"); ("enc", `String "A256CBC-HS512") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let payload = "Secret message protected with A256CBC-HS512" in
          let jwe = Jose.Jwe.make ~header payload |> CCResult.get_exn in
          Alcotest.(check int)
            "A256CBC-HS512 CEK length must be 64 bytes (512 bits)" 64
            (String.length jwe.cek);
          Alcotest.(check int)
            "A256CBC-HS512 IV length must be 16 bytes (128 bits)" 16
            (String.length jwe.iv);
          let encrypted =
            Jose.Jwe.encrypt ~jwk:rsa_priv_jwk jwe |> CCResult.get_exn
          in
          let segs = String.split_on_char '.' encrypted in
          let auth_tag =
            url_decode_string (List.nth segs 4) |> CCResult.get_exn
          in
          Alcotest.(check int)
            "A256CBC-HS512 Auth Tag length must be 32 bytes (256 bits)" 32
            (String.length auth_tag);
          let decrypted = Jose.Jwe.decrypt ~jwk:rsa_priv_jwk encrypted in
          check_result_string "decrypted payload matches" (Ok payload)
            (Result.map Jose.Jwe.(fun d -> d.payload) decrypted);
          check_result_string "decrypted CEK matches" (Ok jwe.cek)
            (Result.map Jose.Jwe.(fun d -> d.cek) decrypted);
          check_result_string "decrypted IV matches" (Ok jwe.iv)
            (Result.map Jose.Jwe.(fun d -> d.iv) decrypted));
      Alcotest.test_case
        "5.2.5: A256CBC-HS512 JWE RSA1_5 encryption and decryption roundtrip"
        `Quick (fun () ->
          let header_json =
            `Assoc
              [ ("alg", `String "RSA1_5"); ("enc", `String "A256CBC-HS512") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let payload = "A256CBC-HS512 with RSA1_5 key management" in
          let jwe = Jose.Jwe.make ~header payload |> CCResult.get_exn in
          let encrypted =
            Jose.Jwe.encrypt ~jwk:rsa_priv_jwk jwe |> CCResult.get_exn
          in
          let segs = String.split_on_char '.' encrypted in
          let auth_tag =
            url_decode_string (List.nth segs 4) |> CCResult.get_exn
          in
          Alcotest.(check int)
            "A256CBC-HS512 Auth Tag length must be 32 bytes (256 bits)" 32
            (String.length auth_tag);
          let decrypted =
            Jose.Jwe.decrypt ~jwk:rsa_priv_jwk encrypted |> CCResult.get_exn
          in
          check_string "decrypted payload matches" payload decrypted.payload);
      Alcotest.test_case
        "5.2.5: A256CBC-HS512 tampering detection on ciphertext and auth tag"
        `Quick (fun () ->
          let header_json =
            `Assoc
              [ ("alg", `String "RSA-OAEP"); ("enc", `String "A256CBC-HS512") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe =
            Jose.Jwe.make ~header "Integrity test for A256CBC-HS512"
            |> CCResult.get_exn
            |> Jose.Jwe.encrypt ~jwk:rsa_priv_jwk
            |> CCResult.get_exn
          in
          let segs = String.split_on_char '.' jwe in
          let tampered_ciphertext_jwe =
            String.concat "."
              [
                List.nth segs 0;
                List.nth segs 1;
                List.nth segs 2;
                url_encode_string "corrupted_ciphertext_bytes_here";
                List.nth segs 4;
              ]
          in
          let res1 =
            Jose.Jwe.decrypt ~jwk:rsa_priv_jwk tampered_ciphertext_jwe
          in
          Alcotest.(check bool)
            "decryption fails on tampered ciphertext" true
            (CCResult.is_error res1);
          let tampered_tag_jwe =
            String.concat "."
              [
                List.nth segs 0;
                List.nth segs 1;
                List.nth segs 2;
                List.nth segs 3;
                url_encode_string "corrupted_auth_tag_bytes_here_32";
              ]
          in
          let res2 = Jose.Jwe.decrypt ~jwk:rsa_priv_jwk tampered_tag_jwe in
          Alcotest.(check bool)
            "decryption fails on tampered auth tag" true
            (CCResult.is_error res2));
      (* =================================================================== *)
      (* Missing Recommended / Recommended+ Algorithms from RFC 7518         *)
      (* =================================================================== *)
      Alcotest.test_case
        "5.1 / 5.3: A128GCM (Recommended) header parsing, sizing (16B CEK, 12B \
         IV), and roundtrip"
        `Quick (fun () ->
          let header_json =
            `Assoc [ ("alg", `String "RSA-OAEP"); ("enc", `String "A128GCM") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let payload = "A128GCM Recommended content encryption" in
          let jwe = Jose.Jwe.make ~header payload |> CCResult.get_exn in
          Alcotest.(check int)
            "A128GCM CEK length must be 16 bytes (128 bits)" 16
            (String.length jwe.cek);
          Alcotest.(check int)
            "A128GCM IV length must be 12 bytes (96 bits)" 12
            (String.length jwe.iv);
          let encrypted =
            Jose.Jwe.encrypt ~jwk:rsa_priv_jwk jwe |> CCResult.get_exn
          in
          let decrypted =
            Jose.Jwe.decrypt ~jwk:rsa_priv_jwk encrypted |> CCResult.get_exn
          in
          check_string "decrypted payload matches" payload decrypted.payload);
      Alcotest.test_case
        "4.1 / 4.5: dir (Recommended) Direct Encryption with symmetric key \
         (RFC 7520 5.6)"
        `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rfc7520_oct_128gcm_key
            |> CCResult.get_exn
          in
          let decrypted = Jose.Jwe.decrypt ~jwk rfc7520_5_6_jwe in
          check_result_string "decrypted payload matches RFC 7520 5.6"
            (Ok frodo_payload)
            (Result.map (fun d -> d.Jose.Jwe.payload) decrypted);
          check_result_bool "header alg is dir" (Ok true)
            (Result.map (fun d -> d.Jose.Jwe.header.alg = `Dir) decrypted);
          (* Test roundtrip direct encryption *)
          let header_json =
            `Assoc [ ("alg", `String "dir"); ("enc", `String "A128GCM") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe =
            Jose.Jwe.make ~header "direct payload" |> CCResult.get_exn
          in
          let encrypted = Jose.Jwe.encrypt ~jwk jwe |> CCResult.get_exn in
          let segs = String.split_on_char '.' encrypted in
          Alcotest.(check string)
            "dir JWE encrypted key segment must be empty" "" (List.nth segs 1);
          let roundtrip = Jose.Jwe.decrypt ~jwk encrypted |> CCResult.get_exn in
          check_string "roundtrip payload matches" "direct payload"
            roundtrip.payload);
      Alcotest.test_case
        "4.1 / 4.4: A128KW & A256KW (Recommended) AES Key Wrap (RFC 7516 A.3 & \
         RFC 7520 5.8)"
        `Quick (fun () ->
          (* Validate RFC 7516 A.3 *)
          let jwk_a3 =
            Jose.Jwk.of_priv_json_string rfc7516_a3_oct_key |> CCResult.get_exn
          in
          let dec_a3 = Jose.Jwe.decrypt ~jwk:jwk_a3 rfc7516_a3_jwe in
          check_result_string "RFC 7516 A.3 decrypted payload"
            (Ok "Live long and prosper.")
            (Result.map (fun dec -> dec.Jose.Jwe.payload) dec_a3);
          (* Validate RFC 7520 5.8 *)
          let jwk_5_8 =
            Jose.Jwk.of_priv_json_string rfc7520_5_8_oct_key |> CCResult.get_exn
          in
          let dec_5_8 = Jose.Jwe.decrypt ~jwk:jwk_5_8 rfc7520_5_8_jwe in
          check_result_string "RFC 7520 5.8 decrypted payload"
            (Ok frodo_payload)
            (Result.map (fun dec -> dec.Jose.Jwe.payload) dec_5_8);
          (* Roundtrip with A128KW *)
          let header_json =
            `Assoc
              [ ("alg", `String "A128KW"); ("enc", `String "A128CBC-HS256") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe =
            Jose.Jwe.make ~header "A128KW roundtrip test" |> CCResult.get_exn
          in
          let enc = Jose.Jwe.encrypt ~jwk:jwk_a3 jwe |> CCResult.get_exn in
          let dec = Jose.Jwe.decrypt ~jwk:jwk_a3 enc |> CCResult.get_exn in
          check_string "A128KW roundtrip matches" "A128KW roundtrip test"
            dec.payload);
      Alcotest.test_case
        "4.1 / 4.6: ECDH-ES (Recommended+) Direct Key Agreement (RFC 7520 5.5)"
        `Quick (fun () ->
          let jwk_recip =
            Jose.Jwk.of_priv_json_string rfc7520_5_5_ec_priv |> CCResult.get_exn
          in
          let dec = Jose.Jwe.decrypt ~jwk:jwk_recip rfc7520_5_5_jwe in
          check_result_string "RFC 7520 5.5 decrypted payload"
            (Ok frodo_payload)
            (Result.map (fun dec -> dec.Jose.Jwe.payload) dec);
          (* Roundtrip ECDH-ES with EC recipient public key *)
          let pub_recip = Jose.Jwk.pub_of_priv jwk_recip in
          let header_json =
            `Assoc
              [ ("alg", `String "ECDH-ES"); ("enc", `String "A128CBC-HS256") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe =
            Jose.Jwe.make ~header "ECDH-ES roundtrip test" |> CCResult.get_exn
          in
          let enc = Jose.Jwe.encrypt ~jwk:pub_recip jwe |> CCResult.get_exn in
          let segs = String.split_on_char '.' enc in
          Alcotest.(check string)
            "ECDH-ES direct key agreement encrypted key segment must be empty"
            "" (List.nth segs 1);
          let roundtrip =
            Jose.Jwe.decrypt ~jwk:jwk_recip enc |> CCResult.get_exn
          in
          check_string "ECDH-ES roundtrip payload matches"
            "ECDH-ES roundtrip test" roundtrip.payload);
      Alcotest.test_case
        "4.1 / 4.6: ECDH-ES+A128KW (Recommended) Key Agreement with Key Wrap \
         (RFC 7520 5.4)"
        `Quick (fun () ->
          let jwk_recip =
            Jose.Jwk.of_priv_json_string rfc7520_5_4_ec_priv |> CCResult.get_exn
          in
          let dec =
            Jose.Jwe.decrypt ~jwk:jwk_recip rfc7520_5_4_jwe |> CCResult.get_exn
          in
          check_string "RFC 7520 5.4 decrypted payload" frodo_payload
            dec.payload;
          (* Roundtrip ECDH-ES+A128KW with EC recipient public key *)
          let pub_recip = Jose.Jwk.pub_of_priv jwk_recip in
          let header_json =
            `Assoc
              [ ("alg", `String "ECDH-ES+A128KW"); ("enc", `String "A128GCM") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe =
            Jose.Jwe.make ~header "ECDH-ES+A128KW roundtrip test"
            |> CCResult.get_exn
          in
          let enc = Jose.Jwe.encrypt ~jwk:pub_recip jwe |> CCResult.get_exn in
          let roundtrip =
            Jose.Jwe.decrypt ~jwk:jwk_recip enc |> CCResult.get_exn
          in
          check_string "ECDH-ES+A128KW roundtrip payload matches"
            "ECDH-ES+A128KW roundtrip test" roundtrip.payload);
      Alcotest.test_case
        "4.1 / 4.6: ECDH-ES+A256KW (Recommended) Key Agreement with Key Wrap"
        `Quick (fun () ->
          let jwk_recip =
            Jose.Jwk.of_priv_json_string rfc7520_5_4_ec_priv |> CCResult.get_exn
          in
          let pub_recip = Jose.Jwk.pub_of_priv jwk_recip in
          let header_json =
            `Assoc
              [ ("alg", `String "ECDH-ES+A256KW"); ("enc", `String "A256GCM") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe =
            Jose.Jwe.make ~header "ECDH-ES+A256KW roundtrip test"
            |> CCResult.get_exn
          in
          let enc = Jose.Jwe.encrypt ~jwk:pub_recip jwe |> CCResult.get_exn in
          let roundtrip =
            Jose.Jwe.decrypt ~jwk:jwk_recip enc |> CCResult.get_exn
          in
          check_string "ECDH-ES+A256KW roundtrip payload matches"
            "ECDH-ES+A256KW roundtrip test" roundtrip.payload);
      Alcotest.test_case "Appendix B.1: AES_128_CBC_HMAC_SHA_256 test vectors"
        `Quick (fun () ->
          let of_hex s =
            let clean =
              CCString.replace ~sub:" " ~by:"" s
              |> CCString.replace ~sub:"\n" ~by:""
            in
            let len = String.length clean in
            let b = Bytes.create (len / 2) in
            for i = 0 to (len / 2) - 1 do
              let byte = int_of_string ("0x" ^ String.sub clean (i * 2) 2) in
              Bytes.set_uint8 b i byte
            done;
            Bytes.to_string b
          in
          let mac_key =
            of_hex "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
          in
          let enc_key =
            of_hex "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
          in
          let p =
            "A cipher system must not be required to be secret, and it must be \
             able to fall into the hands of the enemy without inconvenience"
          in
          let iv = of_hex "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04" in
          let a = "The second principle of Auguste Kerckhoffs" in
          let expected_e =
            of_hex
              "c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79 a2 e4 6a 1b 80 \
               49 f7 92 f7 6b fe 54 b9 03 a9 c9 a9 4a c9 b4 7a d2 65 5c 5f 10 \
               f9 ae f7 14 27 e2 fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 \
               36 09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8 6e 13 33 14 \
               c5 40 19 e8 ca 79 80 df a4 b9 cf 1b 38 4c 48 6f 3a 54 c5 10 78 \
               15 8e e5 d7 9d e5 9f bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 \
               ad e5 4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db"
          in
          let expected_t =
            of_hex "65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4"
          in
          let padded = Jose.Private.Utils.Pkcs7.pad p 16 in
          let key = Mirage_crypto.AES.CBC.of_secret enc_key in
          let e = Mirage_crypto.AES.CBC.encrypt ~key ~iv padded in
          check_string "Appendix B.1 ciphertext matches" expected_e e;
          let al = Bytes.create 8 in
          Bytes.set_int64_be al 0 Int64.(mul 8L (of_int (String.length a)));
          let hmac_input = String.concat "" [ a; iv; e; Bytes.to_string al ] in
          let full_h =
            Digestif.SHA256.hmac_string ~key:mac_key hmac_input
            |> Digestif.SHA256.to_raw_string
          in
          let t = String.sub full_h 0 16 in
          check_string "Appendix B.1 authentication tag matches" expected_t t);
      Alcotest.test_case "Appendix B.3: AES_256_CBC_HMAC_SHA_512 test vectors"
        `Quick (fun () ->
          let of_hex s =
            let clean =
              CCString.replace ~sub:" " ~by:"" s
              |> CCString.replace ~sub:"\n" ~by:""
            in
            let len = String.length clean in
            let b = Bytes.create (len / 2) in
            for i = 0 to (len / 2) - 1 do
              let byte = int_of_string ("0x" ^ String.sub clean (i * 2) 2) in
              Bytes.set_uint8 b i byte
            done;
            Bytes.to_string b
          in
          let mac_key =
            of_hex
              "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 \
               15 16 17 18 19 1a 1b 1c 1d 1e 1f"
          in
          let enc_key =
            of_hex
              "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 \
               35 36 37 38 39 3a 3b 3c 3d 3e 3f"
          in
          let p =
            "A cipher system must not be required to be secret, and it must be \
             able to fall into the hands of the enemy without inconvenience"
          in
          let iv = of_hex "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04" in
          let a = "The second principle of Auguste Kerckhoffs" in
          let expected_e =
            of_hex
              "4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd 3d d8 d5 d3 02 \
               42 35 26 91 2d a0 37 ec bc c7 bd 82 2c 30 1d d6 7c 37 3b cc b5 \
               84 ad 3e 92 79 c2 e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 \
               6b 36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1 1a 09 cc f5 \
               37 0d c8 0b fe cb ad 28 c7 3f 09 b3 a3 b7 5e 66 2a 25 94 41 0a \
               e4 96 b2 e2 e6 60 9e 31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 \
               95 0b be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6"
          in
          let expected_t =
            of_hex
              "4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf 2e 62 69 a8 c5 \
               6a 81 6d bc 1b 26 77 61 95 5b c5"
          in
          let padded = Jose.Private.Utils.Pkcs7.pad p 16 in
          let key = Mirage_crypto.AES.CBC.of_secret enc_key in
          let e = Mirage_crypto.AES.CBC.encrypt ~key ~iv padded in
          check_string "Appendix B.3 ciphertext matches" expected_e e;
          let al = Bytes.create 8 in
          Bytes.set_int64_be al 0 Int64.(mul 8L (of_int (String.length a)));
          let hmac_input = String.concat "" [ a; iv; e; Bytes.to_string al ] in
          let full_h =
            Digestif.SHA512.hmac_string ~key:mac_key hmac_input
            |> Digestif.SHA512.to_raw_string
          in
          let t = String.sub full_h 0 32 in
          check_string "Appendix B.3 authentication tag matches" expected_t t);
      Alcotest.test_case
        "Appendix C: Full ECDH-ES key agreement computation and JWE decryption"
        `Quick (fun () ->
          let bob_priv_json =
            {|{"kty":"EC",
               "crv":"P-256",
               "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
               "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
               "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}|}
          in
          let bob_priv =
            Jose.Jwk.of_priv_json_string bob_priv_json |> CCResult.get_exn
          in
          let alice_epk_json =
            {|{"kty":"EC",
               "crv":"P-256",
               "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
               "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}|}
          in
          let header_json =
            `Assoc
              [
                ("alg", `String "ECDH-ES");
                ("enc", `String "A128GCM");
                ("apu", `String "QWxpY2U");
                ("apv", `String "Qm9i");
                ("epk", Yojson.Safe.from_string alice_epk_json);
              ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let payload =
            "Secret message from Alice to Bob per RFC 7518 Appendix C"
          in
          (* CEK derived per RFC 7518 Appendix C is "VqqN6vgjbSBcIijNcacQGg" *)
          let expected_cek_b64 = "VqqN6vgjbSBcIijNcacQGg" in
          let derived_cek =
            url_decode_string expected_cek_b64 |> CCResult.get_exn
          in
          let iv = Mirage_crypto_rng.generate 12 in
          let header_str = Jose.Header.to_string header in
          let module GCM = Mirage_crypto.AES.GCM in
          let gcm_key = GCM.of_secret derived_cek in
          let cdata =
            GCM.authenticate_encrypt ~key:gcm_key ~nonce:iv ~adata:header_str
              payload
          in
          let ciphertext, tag =
            Jose.Private.Utils.U_String.split cdata
              (String.length cdata - GCM.tag_size)
          in
          let jwe_compact =
            String.concat "."
              [
                header_str;
                "";
                url_encode_string iv;
                url_encode_string ciphertext;
                url_encode_string tag;
              ]
          in
          let decrypted = Jose.Jwe.decrypt ~jwk:bob_priv jwe_compact in
          Alcotest.(check bool)
            "Bob decrypts JWE successfully" true (CCResult.is_ok decrypted);
          let d = CCResult.get_exn decrypted in
          check_string "decrypted payload matches" payload d.payload;
          check_string "derived CEK matches RFC 7518 Appendix C"
            expected_cek_b64 (url_encode_string d.cek));
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7518" [ jwa_tests ]
