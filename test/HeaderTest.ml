let () = Mirage_crypto_rng_unix.use_default ()

open Helpers

let header_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "Header"
    [
      ( "Header",
        [
          Alcotest.test_case "make_header default alg for all key types" `Quick
            (fun () ->
              let rsa_jwk =
                Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let oct_jwk = Jose.Jwk.make_oct "secret" in
              let es256_jwk =
                Jose.Jwk.of_priv_pem Fixtures.es256_test_priv
                |> CCResult.get_exn
              in
              let es384_priv, _ = Mirage_crypto_ec.P384.Dsa.generate () in
              let es384_jwk =
                Jose.Jwk.of_priv_x509 (`P384 es384_priv) |> CCResult.get_exn
              in
              let es512_jwk =
                Jose.Jwk.of_priv_pem Fixtures.es512_test_priv
                |> CCResult.get_exn
              in
              let ed_priv, _ = Mirage_crypto_ec.Ed25519.generate () in
              let ed_jwk =
                Jose.Jwk.Ed25519_priv
                  {
                    alg = None;
                    kty = `OKP;
                    use = None;
                    kid = None;
                    key = ed_priv;
                  }
              in

              check_string "RSA default alg" "RS256"
                ((Jose.Header.make_header rsa_jwk).alg
                |> Jose.Jwa.alg_to_string);
              check_string "Oct default alg" "HS256"
                ((Jose.Header.make_header oct_jwk).alg
                |> Jose.Jwa.alg_to_string);
              check_string "ES256 default alg" "ES256"
                ((Jose.Header.make_header es256_jwk).alg
                |> Jose.Jwa.alg_to_string);
              check_string "ES384 default alg" "ES384"
                ((Jose.Header.make_header es384_jwk).alg
                |> Jose.Jwa.alg_to_string);
              check_string "ES512 default alg" "ES512"
                ((Jose.Header.make_header es512_jwk).alg
                |> Jose.Jwa.alg_to_string);
              check_string "Ed25519 default alg" "EdDSA"
                ((Jose.Header.make_header ed_jwk).alg
                |> Jose.Jwa.alg_to_string));
          Alcotest.test_case "make_header with custom kid in extra" `Quick
            (fun () ->
              let rsa_jwk =
                Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let header =
                Jose.Header.make_header
                  ~extra:[ ("kid", `String "custom-kid") ]
                  rsa_jwk
              in
              check_option_string "overridden kid" "custom-kid" header.kid);
          Alcotest.test_case "make_header with jwk_header = true" `Quick
            (fun () ->
              let rsa_jwk =
                Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let header =
                Jose.Header.make_header ~jwk_header:true rsa_jwk
              in
              Alcotest.(check bool) "jwk is present" true (Option.is_some header.jwk));
          Alcotest.test_case "Header to_json and of_json with all fields" `Quick
            (fun () ->
              let rsa_pub =
                Jose.Jwk.of_pub_pem Fixtures.rsa_test_pub |> CCResult.get_exn
              in
              let header : Jose.Header.t =
                {
                  alg = `RS256;
                  jwk = Some rsa_pub;
                  kid = Some "test-kid";
                  x5t = Some "x5t-thumb";
                  x5t256 = Some "x5t256-thumb";
                  typ = Some "JWT";
                  cty = Some "text/plain";
                  enc = Some `A256GCM;
                  extra = [ ("custom", `String "val") ];
                }
              in
              let json = Jose.Header.to_json header in
              let parsed = Jose.Header.of_json json |> CCResult.get_exn in
              check_string "alg" "RS256" (Jose.Jwa.alg_to_string parsed.alg);
              check_option_string "kid" "test-kid" parsed.kid;
              check_option_string "x5t" "x5t-thumb" parsed.x5t;
              check_option_string "x5t256" "x5t256-thumb" parsed.x5t256;
              check_option_string "typ" "JWT" parsed.typ;
              check_option_string "cty" "text/plain" parsed.cty;
              check_string "enc" "A256GCM"
                (Option.map Jose.Jwa.enc_to_string parsed.enc
                |> Option.value ~default:"");
              check_string "extra" {|`String ("val")|}
                (List.assoc "custom" parsed.extra |> Yojson.Safe.show));
          Alcotest.test_case "Header of_json with non-assoc json" `Quick
            (fun () ->
              let res1 = Jose.Header.of_json (`List []) in
              Alcotest.(check bool) "fails cleanly on non-assoc" true
                (CCResult.is_error res1);
              let res2 = Jose.Header.of_json (`String "not an object") in
              Alcotest.(check bool) "fails cleanly on string" true
                (CCResult.is_error res2));
          Alcotest.test_case "Header of_json with type error in field" `Quick
            (fun () ->
              let res = Jose.Header.of_json (`Assoc [ ("alg", `Int 123) ]) in
              Alcotest.(check bool) "fails on int alg" true
                (CCResult.is_error res));
          Alcotest.test_case "Header of_string and to_string roundtrip" `Quick
            (fun () ->
              let rsa_jwk =
                Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let header = Jose.Header.make_header ~typ:"JWT" rsa_jwk in
              let str = Jose.Header.to_string header in
              let parsed = Jose.Header.of_string str |> CCResult.get_exn in
              check_string "alg matches" (Jose.Jwa.alg_to_string header.alg)
                (Jose.Jwa.alg_to_string parsed.alg);
              check_option_string "kid matches" (Option.get header.kid)
                parsed.kid;
              check_option_string "typ matches" "JWT" parsed.typ);
          Alcotest.test_case "Header of_string on invalid inputs" `Quick
            (fun () ->
              let res_bad_b64 = Jose.Header.of_string "???not-base64???" in
              Alcotest.(check bool) "fails on bad base64" true
                (CCResult.is_error res_bad_b64);
              let encoded_not_json = url_encode_string "{bad json" in
              let raised =
                try
                  ignore (Jose.Header.of_string encoded_not_json);
                  false
                with Yojson.Json_error _ -> true
              in
              Alcotest.(check bool) "fails on malformed json" true raised);
        ] );
    ]
