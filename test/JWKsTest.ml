open Helpers

let trimed_json =
  Fixtures.public_jwk_string
  |> CCString.replace ~sub:" " ~by:""
  |> CCString.replace ~sub:"\n" ~by:""

let expected_jwks_string = {|{"keys":[|} ^ trimed_json ^ "]}"

let jwks_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWKs"
    [
      ( "JWKs",
        [
          Alcotest.test_case "Creates a correct JSON form a JWKs" `Quick
            (fun () ->
              check_string "to_string works" expected_jwks_string
                (Jose.Jwks.to_string
                   { keys = [ Jose.Jwk.Pub.RSA Fixtures.public_jwk ] }));
          Alcotest.test_case "Creates a correct JWKs from JSON" `Quick
            (fun () ->
              let jwks = Jose.Jwks.of_string expected_jwks_string in
              let jwk = Jose.Jwks.find_key jwks Fixtures.public_jwk.kid in
              check_option_string "correct kid" (Some Fixtures.public_jwk.kid)
                (CCOpt.map Jose.Jwk.Pub.get_kid jwk));
          Alcotest.test_case "Parses without alg" `Quick (fun () ->
              let jwks =
                Jose.Jwks.of_string Fixtures.jwks_string_from_oidc_validation
              in
              check_int "Should have 2 JWKs since we don't handle EC" 2
                (List.length jwks.keys));
        ] );
    ]

let jwks_suite = jwks_suite
