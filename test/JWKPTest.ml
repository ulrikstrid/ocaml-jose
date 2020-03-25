open Helpers

let jwk_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWK"
    [
      ( "JwkP",
        [
          Alcotest.test_case "pub - Creates a correct JWK from pem" `Quick
            (fun () ->
              let open Jose.JwkP in
              let jwk = of_pub_pem Fixtures.rsa_test_pub in
              check_result_string "correct kty"
                (Ok (Jose.Jwa.kty_to_string Fixtures.public_jwk.kty))
                (CCResult.map
                   (fun jwk -> get_kty jwk |> Jose.Jwa.kty_to_string)
                   jwk)
              (* check_result_string "correct kid" (Ok Fixtures.public_jwk.kid)
                (CCResult.map (fun jwk -> jwk.kid) jwk)*));
          Alcotest.test_case "pub - Roundtrip rsa" `Quick (fun () ->
              let pub_cert =
                Jose.JwkP.of_pub_pem Fixtures.rsa_test_pub
                |> CCResult.flat_map Jose.JwkP.to_pub_pem
              in
              check_result_string "matches rsa_test_pub"
                (Ok Fixtures.rsa_test_pub) pub_cert);
          Alcotest.test_case "pub - of_pub_json_string" `Quick (fun () ->
              let jwk_r =
                Jose.JwkP.of_pub_json_string Fixtures.public_jwk_string
              in
              (* check_result_string "correct kid" (Ok Fixtures.public_jwk.kid)
                (CCResult.map Jose.JwkP.get_kid jwk_r); *)
              check_result_string "correct kty"
                (Ok (Fixtures.public_jwk.kty |> Jose.Jwa.kty_to_string))
                (CCResult.map
                   (fun jwk ->
                     jwk |> Jose.JwkP.get_kty |> Jose.Jwa.kty_to_string)
                   jwk_r);
              check_result_string "correct alg"
                (Ok (Fixtures.public_jwk.alg |> Jose.Jwa.alg_to_string))
                (CCResult.map
                   (fun jwk ->
                     jwk |> Jose.JwkP.get_alg |> Jose.Jwa.alg_to_string)
                   jwk_r));
          Alcotest.test_case "pub - make_oct" `Quick (fun () ->
              let open Jose.JwkP in
              let[@ocaml.warning "-8"] (Oct oct) =
                make_oct "06c3bd5c-0f97-4b3e-bf20-eb29ae9363de"
              in
              check_string "correct k" Fixtures.oct_jwk_pub.k oct.key
              (*check_string "correct kid" Fixtures.oct_jwk_pub.kid oct.kid);*));
          Alcotest.test_case "pub - to_pub_json_string oct" `Quick (fun () ->
              check_string "correct jwk" Fixtures.oct_jwk_string
                (Jose.JwkP.to_pub_json_string
                   (Jose.JwkP.make_oct "06c3bd5c-0f97-4b3e-bf20-eb29ae9363de")));
          Alcotest.test_case "pub - to_pub_json_string rsa" `Quick (fun () ->
              let jwk =
                Jose.JwkP.of_pub_json_string Fixtures.public_jwk_string
                |> CCResult.get_exn
              in
              check_string "correct jwk"
                (trim_json_string Fixtures.public_jwk_string)
                (Jose.JwkP.to_pub_json_string jwk));
          Alcotest.test_case "priv - to_pub_json_string rsa" `Quick (fun () ->
              let jwk =
                Jose.JwkP.of_priv_json_string Fixtures.private_jwk_string
                |> CCResult.get_exn
              in
              check_string "correct jwk"
                (trim_json_string Fixtures.public_jwk_string)
                (Jose.JwkP.to_pub_json_string jwk));
          Alcotest.test_case "pub - of_pub_json_string oct" `Quick (fun () ->
              let jwk =
                Jose.JwkP.of_pub_json_string Fixtures.oct_jwk_string
                |> CCResult.get_exn
              in
              let[@ocaml.warning "-8"] (Jose.JwkP.Oct oct) = jwk in
              check_string "correct k" Fixtures.oct_jwk_pub.k oct.key;
              check_string "correct kty"
                (Fixtures.oct_jwk_priv.kty |> Jose.Jwa.kty_to_string)
                (jwk |> Jose.JwkP.get_kty |> Jose.Jwa.kty_to_string);
              check_string "correct alg"
                (Fixtures.oct_jwk_priv.alg |> Jose.Jwa.alg_to_string)
                (jwk |> Jose.JwkP.get_alg |> Jose.Jwa.alg_to_string));
          Alcotest.test_case "priv - Creates a correct JWK from pem" `Quick
            (fun () ->
              let open Jose.JwkP in
              let jwk = of_priv_pem Fixtures.rsa_test_priv in
              check_result_string "correct kty"
                (Ok (Jose.Jwa.kty_to_string Fixtures.private_jwk.kty))
                (CCResult.map
                   (fun jwk -> get_kty jwk |> Jose.Jwa.kty_to_string)
                   jwk)
              (*check_result_string "correct kid" (Ok Fixtures.private_jwk.kid)
                (CCResult.map (fun jwk -> jwk.kid) jwk)*));
          Alcotest.test_case "priv - of_priv_json_string rsa" `Quick (fun () ->
              let open Jose.JwkP in
              let jwk = of_priv_json_string Fixtures.private_jwk_string in
              (*check_result_string "correct kid" (Ok Fixtures.private_jwk.kid)
                (CCResult.map get_kid jwk);*)
              check_result_string "correct kty"
                (Ok (Fixtures.private_jwk.kty |> Jose.Jwa.kty_to_string))
                (CCResult.map
                   (fun jwk -> jwk |> get_kty |> Jose.Jwa.kty_to_string)
                   jwk);
              check_result_string "correct alg"
                (Ok (Fixtures.private_jwk.alg |> Jose.Jwa.alg_to_string))
                (CCResult.map
                   (fun jwk -> jwk |> get_alg |> Jose.Jwa.alg_to_string)
                   jwk));
          Alcotest.test_case "priv - Roundtrip" `Quick (fun () ->
              let open Jose.JwkP in
              let priv_cert =
                of_priv_pem Fixtures.rsa_test_priv
                |> CCResult.flat_map to_priv_pem
              in
              check_result_string "matches rsa_test_priv"
                (Ok Fixtures.rsa_test_priv) priv_cert);
          Alcotest.test_case "priv - Roundtrip to pub" `Quick (fun () ->
              let open Jose.JwkP in
              let priv_cert =
                of_priv_pem Fixtures.rsa_test_priv
                |> CCResult.flat_map to_pub_pem
              in
              check_result_string "matches rsa_test_priv"
                (Ok Fixtures.rsa_test_pub) priv_cert);
          Alcotest.test_case "priv - to_priv_json_string rsa" `Quick (fun () ->
              let trimed_json = trim_json_string Fixtures.private_jwk_string in
              check_result_string "matches private_jwk_string" (Ok trimed_json)
                ( Jose.JwkP.of_priv_json_string Fixtures.private_jwk_string
                |> CCResult.map Jose.JwkP.to_priv_json_string ));
          Alcotest.test_case "priv - oct_of_string" `Quick (fun () ->
              let open Jose.JwkP in
              let[@ocaml.warning "-8"] (Oct oct) =
                make_oct "06c3bd5c-0f97-4b3e-bf20-eb29ae9363de"
              in
              check_string "correct k" Fixtures.oct_jwk_priv.k oct.key
              (* check_string "correct kid" Fixtures.oct_jwk_priv.kid oct.kid*));
          Alcotest.test_case "priv - to_priv_json_string oct" `Quick (fun () ->
              check_result_string "correct jwk" (Ok Fixtures.oct_jwk_string)
                ( Jose.JwkP.of_priv_json_string Fixtures.oct_jwk_string
                |> CCResult.map Jose.JwkP.to_priv_json_string ));
          Alcotest.test_case "priv - of_priv_json_string oct" `Quick (fun () ->
              let open Jose.JwkP in
              let jwk =
                of_priv_json_string Fixtures.oct_jwk_string |> CCResult.get_exn
              in
              let[@ocaml.warning "-8"] (Oct oct) = jwk in
              check_string "correct k" Fixtures.oct_jwk_priv.k oct.key;
              check_string "correct kty"
                (Fixtures.oct_jwk_priv.kty |> Jose.Jwa.kty_to_string)
                (jwk |> Jose.JwkP.get_kty |> Jose.Jwa.kty_to_string);
              check_string "correct alg"
                (Fixtures.oct_jwk_priv.alg |> Jose.Jwa.alg_to_string)
                (jwk |> Jose.JwkP.get_alg |> Jose.Jwa.alg_to_string));
        ] );
    ]

let jwk_suite = jwk_suite
