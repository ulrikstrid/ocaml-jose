open Helpers

let jwa_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWA"
    [
      ( "JWA",
        [
          Alcotest.test_case "kty_to_string and kty_of_string" `Quick (fun () ->
              let check_kty (kty : Jose.Jwa.kty) (str : string) =
                check_string "to_string" str (Jose.Jwa.kty_to_string kty);
                Alcotest.(check bool)
                  "of_string" true
                  (Jose.Jwa.kty_of_string str = kty)
              in
              check_kty `oct "oct";
              check_kty `RSA "RSA";
              check_kty `EC "EC";
              check_kty `OKP "OKP";
              check_kty (`Unsupported "custom_kty") "custom_kty");
          Alcotest.test_case "alg_to_string and alg_of_string" `Quick (fun () ->
              let check_alg (alg : Jose.Jwa.alg) (str : string) =
                check_string "to_string" str (Jose.Jwa.alg_to_string alg);
                Alcotest.(check bool)
                  "of_string" true
                  (Jose.Jwa.alg_of_string str = alg);
                check_string "to_json" (`String str |> Yojson.Safe.to_string)
                  (Jose.Jwa.alg_to_json alg |> Yojson.Safe.to_string);
                Alcotest.(check bool)
                  "of_json" true
                  (Jose.Jwa.alg_of_json (`String str) = alg)
              in
              check_alg `RS256 "RS256";
              check_alg `HS256 "HS256";
              check_alg `ES256 "ES256";
              check_alg `ES384 "ES384";
              check_alg `ES512 "ES512";
              check_alg `EdDSA "EdDSA";
              check_alg `RSA_OAEP "RSA-OAEP";
              check_alg `RSA1_5 "RSA1_5";
              check_alg `None "none";
              check_alg (`Unsupported "custom_alg") "custom_alg");
          Alcotest.test_case "enc functions" `Quick (fun () ->
              check_string "enc_to_string A128CBC-HS256" "A128CBC-HS256"
                (Jose.Jwa.enc_to_string `A128CBC_HS256);
              check_string "enc_to_string A256GCM" "A256GCM"
                (Jose.Jwa.enc_to_string `A256GCM);
              Alcotest.(check bool)
                "enc_of_string A128CBC-HS256" true
                (Jose.Jwa.enc_of_string "A128CBC-HS256" = `A128CBC_HS256);
              Alcotest.(check bool)
                "enc_of_string A256GCM" true
                (Jose.Jwa.enc_of_string "A256GCM" = `A256GCM);
              Alcotest.check_raises "enc_of_string unknown raises Not_found"
                Not_found (fun () -> ignore (Jose.Jwa.enc_of_string "UNKNOWN")));
        ] );
    ]
