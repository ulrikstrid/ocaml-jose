open Helpers

let get_string_alg jwk : string =
  let alg = Jose.Jwk.get_alg jwk |> Option.get in
  Jose.Jwa.alg_to_string alg

let jwk_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWK"
    [
      ( "JWK",
        [
          Alcotest.test_case "pub - Creates a correct JWK from pem" `Quick
            (fun () ->
              let open Jose.Jwk in
              let jwk = of_pub_pem Fixtures.rsa_test_pub |> CCResult.get_exn in
              check_string "correct kty"
                (Jose.Jwa.kty_to_string Fixtures.public_jwk_kty)
                (get_kty jwk |> Jose.Jwa.kty_to_string);
              check_option_string "correct kid" Fixtures.public_jwk_kid
                (Jose.Jwk.get_kid jwk));
          Alcotest.test_case "pub - Roundtrip rsa" `Quick (fun () ->
              let pub_cert =
                Jose.Jwk.of_pub_pem Fixtures.rsa_test_pub
                |> CCResult.flat_map Jose.Jwk.to_pub_pem
              in
              check_result_string "matches rsa_test_pub"
                (Ok Fixtures.rsa_test_pub) pub_cert);
          Alcotest.test_case "pub - of_pub_json_string" `Quick (fun () ->
              let jwk =
                Jose.Jwk.of_pub_json_string Fixtures.public_jwk_string
                |> CCResult.get_exn
              in
              check_option_string "correct kid" Fixtures.public_jwk_kid
                (Jose.Jwk.get_kid jwk);
              check_string "correct kty"
                (Fixtures.public_jwk_kty |> Jose.Jwa.kty_to_string)
                (Jose.Jwk.get_kty jwk |> Jose.Jwa.kty_to_string);
              check_string "correct alg"
                (Fixtures.public_jwk_alg |> Jose.Jwa.alg_to_string)
                (Jose.Jwk.get_alg jwk |> Option.get |> Jose.Jwa.alg_to_string));
          Alcotest.test_case "pub - make_oct" `Quick (fun () ->
              let open Jose.Jwk in
              let jwk = make_oct Fixtures.oct_key_string in
              let[@ocaml.warning "-8"] (Oct oct) = jwk in
              check_string "correct k" Fixtures.oct_jwk_pub_k oct.key;
              check_option_string "correct kid" Fixtures.oct_jwk_pub_kid
                (get_kid jwk));
          Alcotest.test_case "pub - to_pub_json_string oct" `Quick (fun () ->
              check_string "correct jwk" Fixtures.oct_jwk_string
                (Jose.Jwk.to_pub_json_string
                   (Jose.Jwk.make_oct Fixtures.oct_key_string)));
          Alcotest.test_case "pub - to_pub_json_string rsa" `Quick (fun () ->
              let jwk =
                Jose.Jwk.of_pub_json_string Fixtures.public_jwk_string
                |> CCResult.get_exn
              in
              check_string "correct jwk"
                (trim_json_string Fixtures.public_jwk_string)
                (Jose.Jwk.to_pub_json_string jwk));
          Alcotest.test_case "priv - to_pub_json_string rsa" `Quick (fun () ->
              let jwk =
                Jose.Jwk.of_priv_json_string Fixtures.private_jwk_string
                |> CCResult.get_exn
              in
              check_string "correct jwk"
                (trim_json_string Fixtures.public_jwk_string)
                (Jose.Jwk.to_pub_json_string jwk));
          Alcotest.test_case "pub - of_pub_json_string oct" `Quick (fun () ->
              let jwk =
                Jose.Jwk.of_pub_json_string Fixtures.oct_jwk_string
                |> CCResult.get_exn
              in
              let[@ocaml.warning "-8"] (Jose.Jwk.Oct oct) = jwk in
              check_string "correct k" Fixtures.oct_jwk_pub_k oct.key;
              check_string "correct kty"
                (Fixtures.oct_jwk_priv_kty |> Jose.Jwa.kty_to_string)
                (jwk |> Jose.Jwk.get_kty |> Jose.Jwa.kty_to_string);
              check_string "correct alg"
                (Fixtures.oct_jwk_priv_alg |> Jose.Jwa.alg_to_string)
                (jwk |> Jose.Jwk.get_alg |> Option.get |> Jose.Jwa.alg_to_string));
          Alcotest.test_case "priv - Creates a correct JWK from pem" `Quick
            (fun () ->
              let open Jose.Jwk in
              let jwk =
                of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              check_option_string "correct kid" Fixtures.private_jwk_kid
                (Jose.Jwk.get_kid jwk);
              check_string "correct kty"
                (Jose.Jwa.kty_to_string Fixtures.private_jwk_kty)
                (get_kty jwk |> Jose.Jwa.kty_to_string));
          Alcotest.test_case "priv - of_priv_json_string rsa" `Quick (fun () ->
              let open Jose.Jwk in
              let jwk =
                of_priv_json_string Fixtures.private_jwk_string
                |> CCResult.get_exn
              in
              check_option_string "correct kid" Fixtures.private_jwk_kid
                (get_kid jwk);
              check_string "correct kty"
                (Fixtures.private_jwk_kty |> Jose.Jwa.kty_to_string)
                (jwk |> get_kty |> Jose.Jwa.kty_to_string);
              check_string "correct alg"
                (Fixtures.private_jwk_alg |> Jose.Jwa.alg_to_string)
                (get_alg jwk |> Option.get |> Jose.Jwa.alg_to_string));
          Alcotest.test_case "priv - Roundtrip" `Quick (fun () ->
              let open Jose.Jwk in
              let priv_cert =
                of_priv_pem Fixtures.rsa_test_priv
                |> CCResult.flat_map to_priv_pem
              in
              check_result_string "matches rsa_test_priv"
                (Ok Fixtures.rsa_test_priv) priv_cert);
          Alcotest.test_case "priv - Roundtrip to pub" `Quick (fun () ->
              let open Jose.Jwk in
              let priv_cert =
                of_priv_pem Fixtures.rsa_test_priv
                |> CCResult.flat_map to_pub_pem
              in
              check_result_string "matches rsa_test_priv"
                (Ok Fixtures.rsa_test_pub) priv_cert);
          Alcotest.test_case "priv - to_priv_json_string rsa" `Quick (fun () ->
              let trimed_json = trim_json_string Fixtures.private_jwk_string in
              check_result_string "matches private_jwk_string" (Ok trimed_json)
                (Jose.Jwk.of_priv_json_string Fixtures.private_jwk_string
                |> CCResult.map Jose.Jwk.to_priv_json_string));
          Alcotest.test_case "priv - oct_of_string" `Quick (fun () ->
              let open Jose.Jwk in
              let jwk = make_oct Fixtures.oct_key_string in
              let[@ocaml.warning "-8"] (Oct oct) = jwk in
              check_string "correct k" Fixtures.oct_jwk_priv_k oct.key;
              check_option_string "correct kid" Fixtures.oct_jwk_priv_kid
                (get_kid jwk));
          Alcotest.test_case "priv - to_priv_json_string oct" `Quick (fun () ->
              check_result_string "correct jwk" (Ok Fixtures.oct_jwk_string)
                (Jose.Jwk.of_priv_json_string Fixtures.oct_jwk_string
                |> CCResult.map Jose.Jwk.to_priv_json_string));
          Alcotest.test_case "priv - of_priv_json_string oct" `Quick (fun () ->
              let jwk =
                Jose.Jwk.of_priv_json_string Fixtures.oct_jwk_string
                |> CCResult.get_exn
              in
              let[@ocaml.warning "-8"] (Jose.Jwk.Oct oct) = jwk in
              check_string "correct k" Fixtures.oct_jwk_priv_k oct.key;
              check_string "correct kty"
                (Fixtures.oct_jwk_priv_kty |> Jose.Jwa.kty_to_string)
                (jwk |> Jose.Jwk.get_kty |> Jose.Jwa.kty_to_string);
              check_string "correct alg"
                (Fixtures.oct_jwk_priv_alg |> Jose.Jwa.alg_to_string)
                (Jose.Jwk.get_alg jwk |> Option.get |> Jose.Jwa.alg_to_string));
          Alcotest.test_case "pub - parse without alg and use" `Quick (fun () ->
              check_result_string "correct jwk"
                (Ok
                   "2aff6e30eb11dc76a38ed5d0c1d50fe8d347ffa0cc654edc4a15803f7ae3a784")
                (Jose.Jwk.of_pub_json_string Fixtures.jwk_without_use_and_alg
                |> Result.map Jose.Jwk.get_kid
                |> Result.map Option.get));
          Alcotest.test_case "P256 - thumbprint" `Quick (fun () ->
              let pub_string =
                {|{
                  "crv": "P-256",
                  "kty": "EC",
                  "x": "q3zAwR_kUwtdLEwtB2oVfucXiLHmEhu9bJUFYjJxYGs",
                  "y": "8h0D-ONoU-iZqrq28TyUxEULxuGwJZGMJYTMbeMshvI"
                }|}
              in
              let pub_jwk =
                Jose.Jwk.of_pub_json_string pub_string |> Result.get_ok
              in
              check_result_string "Creates the correct thumbprint"
                (Ok "ZrBaai73Hi8Fg4MElvDGzIne2NsbI75RHubOViHYE5Q")
              @@ Jose.Jwk.get_thumbprint `SHA256 pub_jwk);
          Alcotest.test_case "P256 - thumbprint" `Quick (fun () ->
              let pub_string =
                {|{
                  "crv":"P-521",
                  "kty":"EC",
                  "x":"AIwG869tNnEGIDg2hSyvXKIOk9rWPO_riIixGliBGBV0kB57QoTrjK-g5JCtazDTcBT23igX9gvAVkLvr2oFTQ9p",
                  "y":"AeGZ0Z3JHM1rQWvmmpdfVu0zSNpmu0xPjGUE2hGhloRqF-JJV3aVMS72ZhGlbWi-O7OCcypIfndhpYgrc3qx0Y1w"
                }|}
              in
              let pub_jwk =
                Jose.Jwk.of_pub_json_string pub_string |> Result.get_ok
              in
              check_result_string "Creates the correct thumbprint"
                (Ok "nBBpbUsITZuECZH0WpBqPH4HKwYV3Tx2KDVyNfwvOkU")
              @@ Jose.Jwk.get_thumbprint `SHA256 pub_jwk);
        ] );
    ]

let jwk_suite = jwk_suite
