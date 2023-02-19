let () = Mirage_crypto_rng_unix.initialize ()

open Helpers

let now = Ptime.of_date (2023, 2, 19) |> Option.get

let jwt_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWT"
    [
      ( "JWT",
        [
          Alcotest.test_case "Can validate a RSA256 JWT" `Quick (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_pub_pem Fixtures.rsa_test_pub |> CCResult.get_exn
              in
              let jwt =
                Jwt.unsafe_of_string Fixtures.external_jwt_string
                |> CCResult.flat_map (Jwt.validate ~jwk ~now)
                |> CCResult.get_exn
              in
              check_string "correct payload" {|{"sub":"tester"}|}
                (Yojson.Safe.to_string jwt.payload));
          Alcotest.test_case "Can validate a HS256 JWT" `Quick (fun () ->
              let open Jose in
              let jwk = Jwk.make_oct Fixtures.oct_key_string in
              let jwt =
                Jwt.unsafe_of_string Fixtures.oct_jwt_string
                |> CCResult.flat_map (Jwt.validate ~jwk ~now)
                |> CCResult.get_exn
              in
              check_string "correct payload" {|{"sub":"tester"}|}
                (Yojson.Safe.to_string jwt.payload));
          Alcotest.test_case "Can create a JWT with RSA256" `Quick (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let header : Jose.Header.t = Header.make_header ~typ:"JWT" jwk in
              check_string "Header is correct"
                {|{"typ":"JWT","alg":"RS256","kid":"0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik"}|}
                (Header.to_json header |> Yojson.Safe.to_string);
              check_string "alg is correct" "RS256"
                (Header.to_json header
                |> Yojson.Safe.Util.member "alg"
                |> Yojson.Safe.Util.to_string);
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r = Jwt.sign ~header ~payload jwk in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.external_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can create a JWT with HS256" `Quick (fun () ->
              let open Jose in
              let jwk = Jwk.make_oct Fixtures.oct_key_string in
              let header = Header.make_header ~typ:"JWT" jwk in
              check_string "Header is correct"
                {|{"typ":"JWT","alg":"HS256","kid":"J4xQh7z-EaJI7Py1P4rFf2S0rppP2m4yKrZW4X4Yfuk"}|}
                (Header.to_json header |> Yojson.Safe.to_string);
              check_string "alg is correct" "HS256"
                (Header.to_json header
                |> Yojson.Safe.Util.member "alg"
                |> Yojson.Safe.Util.to_string);
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r = Jwt.sign ~header ~payload jwk in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.oct_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can create a JWT with ES256" `Quick (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.es256_test_priv
                |> CCResult.map_err (function
                     | `Not_rsa ->
                         print_endline "not_rsa";
                         `Not_rsa
                     | `Msg s ->
                         print_endline s;
                         `Msg s)
                |> CCResult.get_exn
              in
              let header = Header.make_header ~typ:"JWT" jwk in
              check_string "Header is correct"
                {|{"typ":"JWT","alg":"ES256","kid":"UX4qu9L7ZyoSFCZRbXifX7aq_xk-PLfPiPys2-KNkAo"}|}
                (Header.to_json header |> Yojson.Safe.to_string);
              check_string "alg is correct" "ES256"
                (Header.to_json header
                |> Yojson.Safe.Util.member "alg"
                |> Yojson.Safe.Util.to_string);
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r = Jwt.sign ~header ~payload jwk in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.es256_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can validate my own RSA JWT (priv rsa)" `Quick
            (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let header = Header.make_header ~typ:"JWT" jwk in
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r =
                Jwt.sign ~header ~payload jwk
                |> CCResult.flat_map (Jwt.validate ~jwk ~now)
              in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.external_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can validate my own RSA JWT (pub rsa)" `Quick
            (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let pub_jwk = Jwk.pub_of_priv jwk in
              let header = Header.make_header ~typ:"JWT" jwk in
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r =
                Jwt.sign ~header ~payload jwk
                |> CCResult.flat_map (Jwt.validate ~jwk:pub_jwk ~now)
              in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.external_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can validate my own OCT JWT" `Quick (fun () ->
              let open Jose in
              let jwk = Jwk.make_oct ~use:`Sig Fixtures.oct_key_string in
              let header = Header.make_header ~typ:"JWT" jwk in
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r =
                Jwt.sign ~header ~payload jwk
                |> CCResult.flat_map (Jwt.validate ~jwk ~now)
              in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.oct_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can validate my own EC JWT (pub es256)" `Quick
            (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn
              in
              let pub_jwk = Jwk.pub_of_priv jwk in
              let header = Header.make_header ~typ:"JWT" jwk in
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r =
                Jwt.sign ~header ~payload jwk
                |> CCResult.flat_map (Jwt.validate ~jwk:pub_jwk ~now)
              in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.es256_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can validate my own EC JWT (pub es256)" `Quick
            (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn
              in
              let pub_jwk = Jwk.pub_of_priv jwk in
              let header = Header.make_header ~typ:"JWT" jwk in
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r =
                Jwt.sign ~header ~payload jwk
                |> CCResult.flat_map (Jwt.validate ~jwk:pub_jwk ~now)
              in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.es256_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can validate my own EC JWT (pub es512)" `Quick
            (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.es512_test_priv |> CCResult.get_exn
              in
              let pub_jwk = Jwk.pub_of_priv jwk in
              let header = Header.make_header ~typ:"JWT" jwk in
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r =
                Jwt.sign ~header ~payload jwk
                |> CCResult.flat_map (Jwt.validate ~jwk:pub_jwk ~now)
              in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.es512_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
          Alcotest.test_case "Can parse JWT without kid" `Quick (fun () ->
              let jwt =
                Jose.Jwt.unsafe_of_string Fixtures.jwt_without_kid
                |> CCResult.get_exn
              in
              check_string "JWT was parsed correctly without kid" "RS256"
                (jwt.header.alg |> Jose.Jwa.alg_to_string));
          Alcotest.test_case "Checks for expiration when calling `of_string`"
            `Quick (fun () ->
              let open Jose in
              let jwt_s =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbSI6ImZvbyIsImV4cCI6MTY0NDkxNTQ4Mn0.HSKBoJuoUSnh-JCxdE5B615qqRlyoThnAvPSnxktgt4"
              in
              let jwt =
                Jwt.of_string ~jwk:(Jwk.make_oct "lol") ~now jwt_s
                |> CCResult.map (fun _ -> assert false)
              in
              check_result_string "expired" jwt (Error `Expired));
          Alcotest.test_case "Expiration in the future doesn't fail" `Quick
            (fun () ->
              let open Jose in
              let exp =
                Ptime.add_span now @@ Ptime.Span.of_int_s 100 |> Option.get
              in
              let jwk = Jwk.make_oct "lol" in
              let jwt =
                Jose.Jwt.sign
                  ~payload:
                    (`Assoc
                      [ ("exp", `Int (Ptime.to_float_s exp |> int_of_float)) ])
                  jwk
              in
              let jwt = (CCResult.flat_map (Jose.Jwt.validate ~now ~jwk)) jwt in

              check_result_string "Not expired"
                (Result.map (fun jwt -> jwt.Jose.Jwt.raw_header) jwt)
                (Ok
                   "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InlhbWVwWDhoUFU4aUtGT2VhU2lCdE5LTkFORlhVOWNlOGNBYnM3bktySTQifQ"));
          Alcotest.test_case "claim getters" `Quick (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let header : Jose.Header.t = Header.make_header ~typ:"JWT" jwk in
              let payload =
                Jwt.empty_payload
                |> Jwt.add_claim "sub" (`String "tester")
                |> Jwt.add_claim "num" (`Int 10)
              in
              let jwt = Jwt.sign ~header ~payload jwk |> CCResult.get_exn in
              check_option_string "Can get string claim" "tester"
                (Jwt.get_string_claim jwt "sub");
              check_option_int "Can get int claim" 10
                (Jwt.get_int_claim jwt "num");
              Alcotest.(check (option int))
                "Returns None on missing claim" None
                (Jwt.get_int_claim jwt "missing"));
          Alcotest.test_case "Can create JWT without header" `Quick (fun () ->
              let open Jose in
              let jwk =
                Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let payload =
                Jwt.empty_payload |> Jwt.add_claim "sub" (`String "tester")
              in
              let jwt_r =
                Jwt.sign ~payload jwk
                |> CCResult.flat_map (Jwt.validate ~jwk ~now)
              in
              check_result_string "JWT is correctly created"
                (Ok Fixtures.external_jwt_string)
                (CCResult.map Jwt.to_string jwt_r));
        ] );
    ]

let jwt_suite = jwt_suite
