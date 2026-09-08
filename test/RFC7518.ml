(* Tests for RFC 7518 (JSON Web Algorithms) *)
let () = Mirage_crypto_rng_unix.use_default ()
let rsa_priv = Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
let rsa_pub = Jose.Jwk.pub_of_priv rsa_priv

let rsa_priv_jwk =
  Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string |> CCResult.get_exn

open Helpers

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
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7518" [ jwa_tests ]
