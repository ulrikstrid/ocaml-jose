(* Tests for RFC 7519 (JSON Web Token) *)
open Helpers

let oct_priv_json =
  {|{"kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }|}

let rfc7519_jwt_str =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
  ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
  ^ "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

let rfc7519_unsecured_jwt_str =
  "eyJhbGciOiJub25lIn0."
  ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

let jwt_tests =
  ( "RFC7519",
    [
      Alcotest.test_case "3.1: Parse and validate example HS256 JWT" `Quick
        (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string oct_priv_json |> CCResult.get_exn
          in
          (* Token exp is 1300819380 (2011-03-22 18:43:00Z) *)
          let now_valid =
            Ptime.of_float_s 1300819300.0 |> CCOption.get_exn_or "valid time"
          in
          let jwt =
            Jose.Jwt.of_string ~jwk ~now:now_valid rfc7519_jwt_str
            |> CCResult.get_exn
          in
          check_option_string "iss claim is joe" "joe"
            (Jose.Jwt.get_string_claim jwt "iss");
          check_option_int "exp claim is 1300819380" 1300819380
            (Jose.Jwt.get_int_claim jwt "exp");
          Alcotest.(check bool)
            "custom claim http://example.com/is_root is true" true
            (Jose.Jwt.get_yojson_claim jwt "http://example.com/is_root"
            = Some (`Bool true));
          Alcotest.(check bool)
            "header typ is JWT" true
            (jwt.header.typ = Some "JWT");
          Alcotest.(check bool)
            "header alg is HS256" true
            (jwt.header.alg = `HS256));
      Alcotest.test_case "3.1: Expired token validation fails with `Expired"
        `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string oct_priv_json |> CCResult.get_exn
          in
          let now_expired =
            Ptime.of_float_s 1300819400.0 |> CCOption.get_exn_or "expired time"
          in
          let res = Jose.Jwt.of_string ~jwk ~now:now_expired rfc7519_jwt_str in
          Alcotest.(check bool)
            "returns Expired error" true
            (match res with Error `Expired -> true | _ -> false));
      Alcotest.test_case "6.1: Parse unsecured JWT with unsafe_of_string"
        `Quick (fun () ->
          let jwt_res = Jose.Jwt.unsafe_of_string rfc7519_unsecured_jwt_str in
          Alcotest.(check bool)
            "unsafe_of_string parses unsecured JWT" true
            (CCResult.is_ok jwt_res);
          let jwt = CCResult.get_exn jwt_res in
          check_option_string "iss claim is joe" "joe"
            (Jose.Jwt.get_string_claim jwt "iss");
          check_option_int "exp claim is 1300819380" 1300819380
            (Jose.Jwt.get_int_claim jwt "exp");
          Alcotest.(check bool)
            "header alg is None" true
            (jwt.header.alg = `None));
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7519" [ jwt_tests ]
