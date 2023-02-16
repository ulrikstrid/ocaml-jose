let () =
  let path = Sys.getenv_opt "REPORT_PATH" in
  let report =
    Junit.make
      [
        JWKsTest.jwks_suite;
        JWKTest.jwk_suite;
        JWSTest.jws_suite;
        JWTTest.jwt_suite;
        JWETest.jwe_suite;
        RFC7515.suite;
        RFC7520.suite;
        RFC7638.suite;
        RFC8037.suite;
      ]
  in
  match path with Some path -> Junit.to_file report path | None -> ()
