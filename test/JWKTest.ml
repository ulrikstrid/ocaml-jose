open Helpers

let jwk_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWK"
    [
      ( "JWK.Pub",
        [
          Alcotest.test_case "Creates a correct JWK from pem" `Quick (fun () ->
              let open Jose.Jwk.Pub in
              let jwk = rsa_of_pub_pem Fixtures.rsa_test_pub in
              check_result_string "correct kty"
                (Ok (Jose.Jwa.kty_to_string Fixtures.public_jwk.kty))
                (CCResult.map
                   (fun jwk -> jwk.kty |> Jose.Jwa.kty_to_string)
                   jwk);
              check_result_string "correct e" (Ok Fixtures.public_jwk.e)
                (CCResult.map (fun jwk -> jwk.e) jwk);
              check_result_string "correct n" (Ok Fixtures.public_jwk.n)
                (CCResult.map (fun jwk -> jwk.n) jwk);
              check_result_string "correct kid" (Ok Fixtures.public_jwk.kid)
                (CCResult.map (fun jwk -> jwk.kid) jwk));
          Alcotest.test_case "Roundtrip rsa" `Quick (fun () ->
              let pub_cert =
                Jose.Jwk.Pub.rsa_of_pub_pem Fixtures.rsa_test_pub
                |> CCResult.flat_map Jose.Jwk.Pub.rsa_to_pub_pem
              in
              check_result_string "matches rsa_test_pub"
                (Ok Fixtures.rsa_test_pub) pub_cert);
          Alcotest.test_case "of_json" `Quick (fun () ->
              let open Jose.Jwk.Pub in
              let jwk_r = Jose.Jwk.Pub.of_string Fixtures.public_jwk_string in
              check_result_string "correct kid" (Ok Fixtures.public_jwk.kid)
                (CCResult.map Jose.Jwk.Pub.get_kid jwk_r);
              check_result_string "correct kty"
                (Ok (Fixtures.public_jwk.kty |> Jose.Jwa.kty_to_string))
                (CCResult.map
                   (fun jwk ->
                     jwk |> Jose.Jwk.Pub.get_kty |> Jose.Jwa.kty_to_string)
                   jwk_r);
              check_result_string "correct alg"
                (Ok (Fixtures.public_jwk.alg |> Jose.Jwa.alg_to_string))
                (CCResult.map
                   (fun jwk ->
                     jwk |> Jose.Jwk.Pub.get_alg |> Jose.Jwa.alg_to_string)
                   jwk_r);
              check_result_string "correct e" (Ok Fixtures.public_jwk.e)
                (CCResult.map
                   (fun [@ocaml.warning "-8"] (Jose.Jwk.Pub.RSA rsa) -> rsa.e)
                   jwk_r);
              check_result_string "correct n" (Ok Fixtures.public_jwk.n)
                (CCResult.map
                   (fun [@ocaml.warning "-8"] (Jose.Jwk.Pub.RSA rsa) -> rsa.n)
                   jwk_r));
          Alcotest.test_case "oct_of_string" `Quick (fun () ->
              let open Jose.Jwk.Pub in
              let oct = oct_of_string "06c3bd5c-0f97-4b3e-bf20-eb29ae9363de" in
              check_string "correct k" Fixtures.oct_jwk_pub.k oct.k;
              check_string "correct kid" Fixtures.oct_jwk_pub.kid oct.kid);
          Alcotest.test_case "to_string oct" `Quick (fun () ->
              let open Jose.Jwk.Pub in
              check_string "correct jwk" Fixtures.oct_jwk_string
                (to_string (OCT Fixtures.oct_jwk_pub)));
          Alcotest.test_case "of_string oct" `Quick (fun () ->
              let open Jose.Jwk.Pub in
              let[@ocaml.warning "-8"] (OCT oct) =
                of_string Fixtures.oct_jwk_string |> CCResult.get_exn
              in
              check_string "correct k" Fixtures.oct_jwk_pub.k oct.k);
        ] );
      ( "JWK.Priv",
        [
          Alcotest.test_case "Creates a correct JWK from pem" `Quick (fun () ->
              let open Jose.Jwk.Priv in
              let jwk = rsa_of_priv_pem Fixtures.rsa_test_priv in
              check_result_string "correct kty"
                (Ok (Jose.Jwa.kty_to_string Fixtures.private_jwk.kty))
                (CCResult.map
                   (fun jwk -> jwk.kty |> Jose.Jwa.kty_to_string)
                   jwk);
              check_result_string "correct e" (Ok Fixtures.private_jwk.e)
                (CCResult.map (fun jwk -> jwk.e) jwk);
              check_result_string "correct n" (Ok Fixtures.private_jwk.n)
                (CCResult.map (fun jwk -> jwk.n) jwk);
              check_result_string "correct d" (Ok Fixtures.private_jwk.d)
                (CCResult.map (fun jwk -> jwk.d) jwk);
              check_result_string "correct p" (Ok Fixtures.private_jwk.p)
                (CCResult.map (fun jwk -> jwk.p) jwk);
              check_result_string "correct q" (Ok Fixtures.private_jwk.q)
                (CCResult.map (fun jwk -> jwk.q) jwk);
              check_result_string "correct dp" (Ok Fixtures.private_jwk.dp)
                (CCResult.map (fun jwk -> jwk.dp) jwk);
              check_result_string "correct dq" (Ok Fixtures.private_jwk.dq)
                (CCResult.map (fun jwk -> jwk.dq) jwk);
              check_result_string "correct qi" (Ok Fixtures.private_jwk.qi)
                (CCResult.map (fun jwk -> jwk.qi) jwk);
              check_result_string "correct kid" (Ok Fixtures.private_jwk.kid)
                (CCResult.map (fun jwk -> jwk.kid) jwk));
          Alcotest.test_case "of_json" `Quick (fun () ->
              let open Jose.Jwk.Priv in
              let jwk = of_string Fixtures.private_jwk_string in
              check_result_string "correct kid" (Ok Fixtures.private_jwk.kid)
                (CCResult.map get_kid jwk);
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
          Alcotest.test_case "Roundtrip" `Quick (fun () ->
              let open Jose.Jwk.Priv in
              let priv_cert =
                rsa_of_priv_pem Fixtures.rsa_test_priv
                |> CCResult.flat_map rsa_to_priv_pem
              in
              check_result_string "matches rsa_test_priv"
                (Ok Fixtures.rsa_test_priv) priv_cert);
          Alcotest.test_case "to_string" `Quick (fun () ->
              let open Jose.Jwk.Priv in
              let trimed_json =
                Fixtures.private_jwk_string
                |> CCString.replace ~sub:" " ~by:""
                |> CCString.replace ~sub:"\n" ~by:""
              in
              check_string "matches private_jwk_string" trimed_json
                (to_string (RSA Fixtures.private_jwk)));
          Alcotest.test_case "oct_of_string" `Quick (fun () ->
              let open Jose.Jwk.Priv in
              let oct = oct_of_string "06c3bd5c-0f97-4b3e-bf20-eb29ae9363de" in
              check_string "correct k" Fixtures.oct_jwk_priv.k oct.k;
              check_string "correct kid" Fixtures.oct_jwk_priv.kid oct.kid);
          Alcotest.test_case "to_string oct" `Quick (fun () ->
              let open Jose.Jwk.Priv in
              check_string "correct jwk" Fixtures.oct_jwk_string
                (to_string (OCT Fixtures.oct_jwk_priv)));
          Alcotest.test_case "of_string oct" `Quick (fun () ->
              let open Jose.Jwk.Priv in
              let[@ocaml.warning "-8"] (OCT oct) =
                of_string Fixtures.oct_jwk_string |> CCResult.get_exn
              in
              check_string "correct k" Fixtures.oct_jwk_priv.k oct.k);
        ] );
    ]

let jwk_suite = jwk_suite
