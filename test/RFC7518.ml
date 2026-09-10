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
  "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MWRiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0."
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
  "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC00MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0."
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
  "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidWNrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZGxvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ."
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
          let decrypted =
            Jose.Jwe.decrypt ~jwk rfc7520_5_6_jwe |> CCResult.get_exn
          in
          check_string "decrypted payload matches RFC 7520 5.6" frodo_payload
            decrypted.payload;
          Alcotest.(check bool)
            "header alg is dir" true
            (decrypted.header.alg = `Unsupported "dir");
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
          let dec_a3 =
            Jose.Jwe.decrypt ~jwk:jwk_a3 rfc7516_a3_jwe |> CCResult.get_exn
          in
          check_string "RFC 7516 A.3 decrypted payload" "Live long and prosper."
            dec_a3.payload;
          (* Validate RFC 7520 5.8 *)
          let jwk_5_8 =
            Jose.Jwk.of_priv_json_string rfc7520_5_8_oct_key |> CCResult.get_exn
          in
          let dec_5_8 =
            Jose.Jwe.decrypt ~jwk:jwk_5_8 rfc7520_5_8_jwe |> CCResult.get_exn
          in
          check_string "RFC 7520 5.8 decrypted payload" frodo_payload
            dec_5_8.payload;
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
          let dec =
            Jose.Jwe.decrypt ~jwk:jwk_recip rfc7520_5_5_jwe |> CCResult.get_exn
          in
          check_string "RFC 7520 5.5 decrypted payload" frodo_payload
            dec.payload;
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
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7518" [ jwa_tests ]
