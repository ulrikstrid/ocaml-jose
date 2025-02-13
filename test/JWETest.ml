let () = Mirage_crypto_rng_unix.use_default ()

open Helpers

let jwe_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWE"
    [
      ( "JWE",
        [
          Alcotest.test_case
            "Can create and validate my own RSA-OAEP with A256GCM JWEs" `Quick
            (fun () ->
              let jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let header =
                Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A256GCM jwk
              in
              let jwe = Jose.Jwe.make ~header "test" |> CCResult.get_exn in
              let jwe_string = Jose.Jwe.encrypt ~jwk jwe |> CCResult.get_exn in
              let decrypted_jwe =
                Jose.Jwe.decrypt ~jwk jwe_string |> CCResult.get_exn
              in
              check_string "to_string works" jwe.payload decrypted_jwe.payload);
          Alcotest.test_case
            "Can create and validate my own RSA_OAEP with A128CBC-HS256 JWEs"
            `Quick (fun () ->
              let jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let header =
                Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A128CBC_HS256 jwk
              in
              let jwe = Jose.Jwe.make ~header "test" |> CCResult.get_exn in
              let jwe_string = Jose.Jwe.encrypt ~jwk jwe |> CCResult.get_exn in
              let decrypted_jwe =
                Jose.Jwe.decrypt ~jwk jwe_string |> CCResult.get_exn
              in
              check_string "to_string works" jwe.payload decrypted_jwe.payload);
          Alcotest.test_case
            "Can create and validate my own RSA1_5 with A128CBC-HS256 JWEs"
            `Quick (fun () ->
              let jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let header =
                Jose.Header.make_header ~alg:`RSA1_5 ~enc:`A128CBC_HS256 jwk
              in
              let jwe = Jose.Jwe.make ~header "test" |> CCResult.get_exn in
              let jwe_string = Jose.Jwe.encrypt ~jwk jwe |> CCResult.get_exn in
              let decrypted_jwe =
                Jose.Jwe.decrypt ~jwk jwe_string |> CCResult.get_exn
              in
              check_string "to_string works" jwe.payload decrypted_jwe.payload);
          Alcotest.test_case
            "Can create and validate my own RSA1_5 with A256GCM JWEs" `Quick
            (fun () ->
              let jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let header =
                Jose.Header.make_header ~alg:`RSA1_5 ~enc:`A256GCM jwk
              in
              let jwe = Jose.Jwe.make ~header "test" |> CCResult.get_exn in
              let jwe_string = Jose.Jwe.encrypt ~jwk jwe |> CCResult.get_exn in
              let decrypted_jwe =
                Jose.Jwe.decrypt ~jwk jwe_string |> CCResult.get_exn
              in
              check_string "to_string works" jwe.payload decrypted_jwe.payload);
        ] );
    ]

let jwe_suite = jwe_suite
