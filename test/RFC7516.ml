(* Tests for RFC 7516 (JSON Web Encryption) and related JWA RFC 7518 algorithms *)
let () = Mirage_crypto_rng_unix.use_default ()

open Helpers

let rsa_priv_jwk =
  Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string |> CCResult.get_exn

let jwe_tests =
  ( "RFC7516",
    [
      Alcotest.test_case "IV length is determined by enc (CBC vs GCM)" `Quick
        (fun () ->
          (* RSA-OAEP paired with CBC must use 16 bytes *)
          let header_cbc =
            Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A128CBC_HS256
              rsa_priv_jwk
          in
          let jwe_cbc =
            Jose.Jwe.make ~header:header_cbc "secret message"
            |> CCResult.get_exn
          in
          Alcotest.(check int)
            "CBC IV length must be 16 bytes" 16 (String.length jwe_cbc.iv);

          (* RSA1_5 paired with GCM must use 12 bytes (96 bits) *)
          let header_gcm =
            Jose.Header.make_header ~alg:`RSA1_5 ~enc:`A256GCM rsa_priv_jwk
          in
          let jwe_gcm =
            Jose.Jwe.make ~header:header_gcm "secret message"
            |> CCResult.get_exn
          in
          Alcotest.(check int)
            "GCM IV length must be 12 bytes" 12 (String.length jwe_gcm.iv));
      Alcotest.test_case
        "PKCS#7 unpadding gracefully handles corrupted padding without \
         exception"
        `Quick (fun () ->
          let header =
            Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A128CBC_HS256
              rsa_priv_jwk
          in
          let jwe =
            Jose.Jwe.make ~header "test payload"
            |> CCResult.get_exn
            |> Jose.Jwe.encrypt ~jwk:rsa_priv_jwk
            |> CCResult.get_exn
          in
          (* Tamper with ciphertext by corrupting bytes *)
          let segs = String.split_on_char '.' jwe in
          let corrupted_jwe =
            String.concat "."
              [
                List.nth segs 0;
                List.nth segs 1;
                List.nth segs 2;
                url_encode_string "\x00\x00\x00\x00\x00\x00\x00\x00";
                List.nth segs 4;
              ]
          in
          let raised =
            try
              let _ = Jose.Jwe.decrypt ~jwk:rsa_priv_jwk corrupted_jwe in
              false
            with Invalid_argument _ -> true
          in
          Alcotest.(check bool)
            "decrypt must return Result.Error and not throw Invalid_argument \
             exception"
            false raised);
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7516" [ jwe_tests ]
