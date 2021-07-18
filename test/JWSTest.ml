let () = Mirage_crypto_rng_unix.initialize ()

open Helpers

let jws_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWS"
    [
      ( "JWS",
        [
          Alcotest.test_case "rfc7515 A.3" `Quick (fun () ->
              let jwk_str =
                {|{"kty":"EC",
"crv":"P-256",
"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
}|}
              in
              let payload_str =
                {|{"iss":"joe",
"exp":1300819380,
"http://example.com/is_root":true
}|}
              in
              let expected_str =
                {|eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q|}
              in
              let jwk =
                Jose.Jwk.of_priv_json_string jwk_str |> CCResult.get_exn
              in
              Jose.Jws.of_string expected_str
              |> CCResult.flat_map (Jose.Jws.validate ~jwk)
              |> CCResult.map (fun (jws : Jose.Jws.t) ->
                   jws.payload |> Yojson.Safe.from_string
                     |> Yojson.Safe.to_string)
              |> check_result_string "Validated payload is correct"
                   (Ok
                      (payload_str |> Yojson.Safe.from_string
                     |> Yojson.Safe.to_string)));
        ] );
    ]

let jws_suite = jws_suite
