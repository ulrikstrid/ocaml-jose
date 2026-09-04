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
          Alcotest.test_case "Can encrypt JWE with Rsa_pub" `Quick (fun () ->
              let priv_jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let pub_jwk = Jose.Jwk.pub_of_priv priv_jwk in
              let header =
                Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A256GCM priv_jwk
              in
              let jwe = Jose.Jwe.make ~header "secret payload" |> CCResult.get_exn in
              let jwe_string = Jose.Jwe.encrypt ~jwk:pub_jwk jwe |> CCResult.get_exn in
              let decrypted =
                Jose.Jwe.decrypt ~jwk:priv_jwk jwe_string |> CCResult.get_exn
              in
              check_string "decrypted payload matches" "secret payload"
                decrypted.payload);
          Alcotest.test_case "make error conditions" `Quick (fun () ->
              let jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let header_no_enc = Jose.Header.make_header ~alg:`RSA_OAEP jwk in
              let res_no_enc = Jose.Jwe.make ~header:header_no_enc "data" in
              Alcotest.(check bool) "fails with Missing_enc" true
                (res_no_enc = Error `Missing_enc);
              let header_bad_alg =
                Jose.Header.make_header ~alg:`HS256 ~enc:`A256GCM jwk
              in
              let res_bad_alg = Jose.Jwe.make ~header:header_bad_alg "data" in
              Alcotest.(check bool) "fails with Unsupported_alg" true
                (res_bad_alg = Error `Unsupported_alg));
          Alcotest.test_case "encrypt error conditions" `Quick (fun () ->
              let rsa_jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let header =
                Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A256GCM rsa_jwk
              in
              let jwe = Jose.Jwe.make ~header "payload" |> CCResult.get_exn in

              let oct_jwk = Jose.Jwk.make_oct "secret" in
              let res_oct = Jose.Jwe.encrypt ~jwk:oct_jwk jwe in
              Alcotest.(check bool) "oct Unsupported_kty" true
                (res_oct = Error `Unsupported_kty);

              let es256_priv, es256_pub = Mirage_crypto_ec.P256.Dsa.generate () in
              let res_es256_priv =
                Jose.Jwe.encrypt
                  ~jwk:(Jose.Jwk.of_priv_x509 (`P256 es256_priv) |> CCResult.get_exn)
                  jwe
              in
              Alcotest.(check bool) "es256_priv Unsupported_kty" true
                (res_es256_priv = Error `Unsupported_kty);
              let res_es256_pub =
                Jose.Jwe.encrypt
                  ~jwk:(Jose.Jwk.of_pub_x509 (`P256 es256_pub) |> CCResult.get_exn)
                  jwe
              in
              Alcotest.(check bool) "es256_pub Unsupported_kty" true
                (res_es256_pub = Error `Unsupported_kty);

              let es384_priv, es384_pub = Mirage_crypto_ec.P384.Dsa.generate () in
              let res_es384_priv =
                Jose.Jwe.encrypt
                  ~jwk:(Jose.Jwk.of_priv_x509 (`P384 es384_priv) |> CCResult.get_exn)
                  jwe
              in
              Alcotest.(check bool) "es384_priv Unsupported_kty" true
                (res_es384_priv = Error `Unsupported_kty);
              let res_es384_pub =
                Jose.Jwe.encrypt
                  ~jwk:(Jose.Jwk.of_pub_x509 (`P384 es384_pub) |> CCResult.get_exn)
                  jwe
              in
              Alcotest.(check bool) "es384_pub Unsupported_kty" true
                (res_es384_pub = Error `Unsupported_kty);

              let es512_priv, es512_pub = Mirage_crypto_ec.P521.Dsa.generate () in
              let res_es512_priv =
                Jose.Jwe.encrypt
                  ~jwk:(Jose.Jwk.of_priv_x509 (`P521 es512_priv) |> CCResult.get_exn)
                  jwe
              in
              Alcotest.(check bool) "es512_priv Unsupported_kty" true
                (res_es512_priv = Error `Unsupported_kty);
              let res_es512_pub =
                Jose.Jwe.encrypt
                  ~jwk:(Jose.Jwk.of_pub_x509 (`P521 es512_pub) |> CCResult.get_exn)
                  jwe
              in
              Alcotest.(check bool) "es512_pub Unsupported_kty" true
                (res_es512_pub = Error `Unsupported_kty);

              let ed_priv, ed_pub = Mirage_crypto_ec.Ed25519.generate () in
              let ed_jwk_priv =
                Jose.Jwk.Ed25519_priv
                  { alg = None; kty = `OKP; use = None; kid = None; key = ed_priv }
              in
              let ed_jwk_pub =
                Jose.Jwk.Ed25519_pub
                  { alg = None; kty = `OKP; use = None; kid = None; key = ed_pub }
              in
              Alcotest.(check bool) "ed_priv Unsupported_kty" true
                (Jose.Jwe.encrypt ~jwk:ed_jwk_priv jwe = Error `Unsupported_kty);
              Alcotest.(check bool) "ed_pub Unsupported_kty" true
                (Jose.Jwe.encrypt ~jwk:ed_jwk_pub jwe = Error `Unsupported_kty);

              let jwe_bad_alg = { jwe with header = { jwe.header with alg = `HS256 } } in
              Alcotest.(check bool) "bad alg Invalid_alg" true
                (Jose.Jwe.encrypt ~jwk:rsa_jwk jwe_bad_alg = Error `Invalid_alg);

              let jwe_no_enc = { jwe with header = { jwe.header with enc = None } } in
              Alcotest.(check bool) "no enc Missing_enc" true
                (Jose.Jwe.encrypt ~jwk:rsa_jwk jwe_no_enc = Error `Missing_enc));
          Alcotest.test_case "decrypt error conditions" `Quick (fun () ->
              let rsa_jwk =
                Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string
                |> CCResult.get_exn
              in
              let header_gcm =
                Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A256GCM rsa_jwk
              in
              let jwe_gcm =
                Jose.Jwe.make ~header:header_gcm "test"
                |> CCResult.get_exn
                |> Jose.Jwe.encrypt ~jwk:rsa_jwk
                |> CCResult.get_exn
              in
              let header_cbc =
                Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A128CBC_HS256 rsa_jwk
              in
              let jwe_cbc =
                Jose.Jwe.make ~header:header_cbc "test"
                |> CCResult.get_exn
                |> Jose.Jwe.encrypt ~jwk:rsa_jwk
                |> CCResult.get_exn
              in

              Alcotest.(check bool) "fails with Invalid_JWE on wrong segment count" true
                (Jose.Jwe.decrypt ~jwk:rsa_jwk "a.b.c" = Error `Invalid_JWE);

              let oct_jwk = Jose.Jwk.make_oct "secret" in
              Alcotest.(check bool) "fails with Invalid_JWK on non-RSA priv" true
                (Jose.Jwe.decrypt ~jwk:oct_jwk jwe_gcm = Error `Invalid_JWK);

              let wrong_rsa_jwk =
                Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              Alcotest.(check bool) "fails with Decrypt_cek_failed on wrong RSA key" true
                (Jose.Jwe.decrypt ~jwk:wrong_rsa_jwk jwe_gcm = Error `Decrypt_cek_failed);

              let segs_gcm = String.split_on_char '.' jwe_gcm in
              let tampered_tag_gcm =
                String.concat "."
                  [
                    List.nth segs_gcm 0;
                    List.nth segs_gcm 1;
                    List.nth segs_gcm 2;
                    List.nth segs_gcm 3;
                    url_encode_string "tamperedtag12345";
                  ]
              in
              Alcotest.(check bool) "fails on tampered GCM tag" true
                (Jose.Jwe.decrypt ~jwk:rsa_jwk tampered_tag_gcm
                = Error (`Msg "invalid auth tag"));

              let segs_cbc = String.split_on_char '.' jwe_cbc in
              let tampered_tag_cbc =
                String.concat "."
                  [
                    List.nth segs_cbc 0;
                    List.nth segs_cbc 1;
                    List.nth segs_cbc 2;
                    List.nth segs_cbc 3;
                    url_encode_string "tamperedtag12345";
                  ]
              in
              Alcotest.(check bool) "fails on tampered CBC tag" true
                (Jose.Jwe.decrypt ~jwk:rsa_jwk tampered_tag_cbc
                = Error (`Msg "invalid auth tag"));

              let header_no_enc = Jose.Header.make_header ~alg:`RSA_OAEP rsa_jwk in
              let jwe_no_enc_str =
                String.concat "."
                  [
                    Jose.Header.to_string header_no_enc;
                    List.nth segs_gcm 1;
                    List.nth segs_gcm 2;
                    List.nth segs_gcm 3;
                    List.nth segs_gcm 4;
                  ]
              in
              Alcotest.(check bool) "fails on missing enc in header" true
                (Jose.Jwe.decrypt ~jwk:rsa_jwk jwe_no_enc_str
                = Error (`Msg "unsupported encryption")));
        ] );
    ]

let jwe_suite = jwe_suite
