let () = Mirage_crypto_rng_unix.use_default ()

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
                Jose.Jwk.of_pub_json_string pub_string |> CCResult.get_exn
              in
              check_result_string "Creates the correct thumbprint"
                (Ok "ZrBaai73Hi8Fg4MElvDGzIne2NsbI75RHubOViHYE5Q")
              @@ Result.map url_encode_string
              @@ Jose.Jwk.get_thumbprint `SHA256 pub_jwk);
          Alcotest.test_case "P384 - thumbprint" `Quick (fun () ->
              let pub_string =
                {|{
                  "crv":"P-384",
                  "kty":"EC",
                  "x":"FqTN7UHEy4MLUQvaB31WtfPcBhmzRS2Xl7jVtM3ELvHBQ6l_WrJqryK2gAoDImRl",
                  "y":"5wlJyPkB7PE2MVdIMoqwclRpnCX3l5w7kIPwE69GGJVMLBxd758jhcptkKVhRjTg"
                }|}
              in
              let pub_jwk = Jose.Jwk.of_pub_json_string pub_string in
              check_result_string "Creates the correct thumbprint"
                (Ok "CZv-vJviuyEXKGIeW2fYpEjRXSxUTHUdoQ58asby1Rg")
              @@ Result.map url_encode_string
              @@ CCResult.flat_map (Jose.Jwk.get_thumbprint `SHA256) pub_jwk);
          Alcotest.test_case "P521 - thumbprint" `Quick (fun () ->
              let pub_string =
                {|{
                  "crv":"P-521",
                  "kty":"EC",
                  "x":"AIwG869tNnEGIDg2hSyvXKIOk9rWPO_riIixGliBGBV0kB57QoTrjK-g5JCtazDTcBT23igX9gvAVkLvr2oFTQ9p",
                  "y":"AeGZ0Z3JHM1rQWvmmpdfVu0zSNpmu0xPjGUE2hGhloRqF-JJV3aVMS72ZhGlbWi-O7OCcypIfndhpYgrc3qx0Y1w"
                }|}
              in
              let pub_jwk =
                Jose.Jwk.of_pub_json_string pub_string |> CCResult.get_exn
              in
              check_result_string "Creates the correct thumbprint"
                (Ok "nBBpbUsITZuECZH0WpBqPH4HKwYV3Tx2KDVyNfwvOkU")
              @@ Result.map url_encode_string
              @@ Jose.Jwk.get_thumbprint `SHA256 pub_jwk);
          Alcotest.test_case "use_to_string and use_of_string" `Quick (fun () ->
              check_string "use sig" "sig" (Jose.Jwk.use_to_string `Sig);
              check_string "use enc" "enc" (Jose.Jwk.use_to_string `Enc);
              check_string "use custom" "custom"
                (Jose.Jwk.use_to_string (`Unsupported "custom"));
              Alcotest.(check bool) "of sig" true (Jose.Jwk.use_of_string "sig" = `Sig);
              Alcotest.(check bool) "of enc" true (Jose.Jwk.use_of_string "enc" = `Enc);
              Alcotest.(check bool) "of custom" true
                (Jose.Jwk.use_of_string "custom" = `Unsupported "custom"));
          Alcotest.test_case "make_priv_rsa and make_pub_rsa with use" `Quick
            (fun () ->
              let priv_rsa_jwk =
                Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
              in
              let[@ocaml.warning "-8"] (Jose.Jwk.Rsa_priv rsa_p) = priv_rsa_jwk in
              let priv_sig = Jose.Jwk.make_priv_rsa ~use:`Sig rsa_p.key in
              let priv_enc = Jose.Jwk.make_priv_rsa ~use:`Enc rsa_p.key in
              let pub_sig = Jose.Jwk.make_pub_rsa ~use:`Sig (Mirage_crypto_pk.Rsa.pub_of_priv rsa_p.key) in
              let pub_enc = Jose.Jwk.make_pub_rsa ~use:`Enc (Mirage_crypto_pk.Rsa.pub_of_priv rsa_p.key) in
              Alcotest.(check bool) "priv_sig alg RS256" true
                (Jose.Jwk.get_alg priv_sig = Some `RS256);
              Alcotest.(check bool) "priv_enc alg RSA_OAEP" true
                (Jose.Jwk.get_alg priv_enc = Some `RSA_OAEP);
              Alcotest.(check bool) "pub_sig alg RS256" true
                (Jose.Jwk.get_alg pub_sig = Some `RS256);
              Alcotest.(check bool) "pub_enc alg RSA_OAEP" true
                (Jose.Jwk.get_alg pub_enc = Some `RSA_OAEP));
          Alcotest.test_case "get_alg, get_kty, get_kid across all key variants" `Quick
            (fun () ->
              let es256_priv = Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn in
              let es256_pub = Jose.Jwk.pub_of_priv es256_priv in
              let es384_p, es384_pub_raw = Mirage_crypto_ec.P384.Dsa.generate () in
              let es384_priv = Jose.Jwk.of_priv_x509 (`P384 es384_p) |> CCResult.get_exn in
              let es384_pub = Jose.Jwk.of_pub_x509 (`P384 es384_pub_raw) |> CCResult.get_exn in
              let es512_priv = Jose.Jwk.of_priv_pem Fixtures.es512_test_priv |> CCResult.get_exn in
              let es512_pub = Jose.Jwk.pub_of_priv es512_priv in
              let ed_p, ed_pub_raw = Mirage_crypto_ec.Ed25519.generate () in
              let ed_priv =
                Jose.Jwk.Ed25519_priv
                  { alg = Some `EdDSA; kty = `OKP; use = Some `Sig; kid = Some "ed-kid"; key = ed_p }
              in
              let ed_pub =
                Jose.Jwk.Ed25519_pub
                  { alg = Some `EdDSA; kty = `OKP; use = Some `Sig; kid = Some "ed-kid"; key = ed_pub_raw }
              in

              (* get_alg *)
              Alcotest.(check bool) "es256_priv alg" true (Jose.Jwk.get_alg es256_priv = Some `ES256);
              Alcotest.(check bool) "es256_pub alg" true (Jose.Jwk.get_alg es256_pub = Some `ES256);
              Alcotest.(check bool) "es384_priv alg" true (Jose.Jwk.get_alg es384_priv = Some `ES384);
              Alcotest.(check bool) "es384_pub alg" true (Jose.Jwk.get_alg es384_pub = Some `ES384);
              Alcotest.(check bool) "es512_priv alg" true (Jose.Jwk.get_alg es512_priv = Some `ES512);
              Alcotest.(check bool) "es512_pub alg" true (Jose.Jwk.get_alg es512_pub = Some `ES512);
              Alcotest.(check bool) "ed_priv alg" true (Jose.Jwk.get_alg ed_priv = Some `EdDSA);
              Alcotest.(check bool) "ed_pub alg" true (Jose.Jwk.get_alg ed_pub = Some `EdDSA);

              (* get_kty *)
              Alcotest.(check bool) "es256_priv kty" true (Jose.Jwk.get_kty es256_priv = `EC);
              Alcotest.(check bool) "es256_pub kty" true (Jose.Jwk.get_kty es256_pub = `EC);
              Alcotest.(check bool) "es384_priv kty" true (Jose.Jwk.get_kty es384_priv = `EC);
              Alcotest.(check bool) "es384_pub kty" true (Jose.Jwk.get_kty es384_pub = `EC);
              Alcotest.(check bool) "es512_priv kty" true (Jose.Jwk.get_kty es512_priv = `EC);
              Alcotest.(check bool) "es512_pub kty" true (Jose.Jwk.get_kty es512_pub = `EC);
              Alcotest.(check bool) "ed_priv kty" true (Jose.Jwk.get_kty ed_priv = `OKP);
              Alcotest.(check bool) "ed_pub kty" true (Jose.Jwk.get_kty ed_pub = `OKP);

              (* get_kid *)
              Alcotest.(check bool) "es256_pub kid" true (Option.is_some (Jose.Jwk.get_kid es256_pub));
              Alcotest.(check bool) "es384_pub kid" true (Option.is_some (Jose.Jwk.get_kid es384_pub));
              Alcotest.(check bool) "es512_pub kid" true (Option.is_some (Jose.Jwk.get_kid es512_pub));
              Alcotest.(check bool) "ed_priv kid" true (Jose.Jwk.get_kid ed_priv = Some "ed-kid");
              Alcotest.(check bool) "ed_pub kid" true (Jose.Jwk.get_kid ed_pub = Some "ed-kid"));
          Alcotest.test_case "PEM roundtrips and error cases for EC and Oct" `Quick
            (fun () ->
              (* ES256 PEM *)
              let es256_priv = Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn in
              let es256_pub = Jose.Jwk.pub_of_priv es256_priv in
              let pem_priv_256 = Jose.Jwk.to_priv_pem es256_priv |> CCResult.get_exn in
              let pem_pub_256 = Jose.Jwk.to_pub_pem es256_pub |> CCResult.get_exn in
              let pem_pub_from_priv_256 = Jose.Jwk.to_pub_pem es256_priv |> CCResult.get_exn in
              Alcotest.(check bool) "reparsed es256 priv" true
                (CCResult.is_ok (Jose.Jwk.of_priv_pem pem_priv_256));
              Alcotest.(check bool) "reparsed es256 pub" true
                (CCResult.is_ok (Jose.Jwk.of_pub_pem pem_pub_256));
              Alcotest.(check bool) "pub pem from priv 256" true
                (pem_pub_256 = pem_pub_from_priv_256);

              (* ES384 PEM *)
              let es384_p, _ = Mirage_crypto_ec.P384.Dsa.generate () in
              let es384_priv = Jose.Jwk.of_priv_x509 (`P384 es384_p) |> CCResult.get_exn in
              let es384_pub = Jose.Jwk.pub_of_priv es384_priv in
              let pem_priv_384 = Jose.Jwk.to_priv_pem es384_priv |> CCResult.get_exn in
              let pem_pub_384 = Jose.Jwk.to_pub_pem es384_pub |> CCResult.get_exn in
              let pem_pub_from_priv_384 = Jose.Jwk.to_pub_pem es384_priv |> CCResult.get_exn in
              Alcotest.(check bool) "reparsed es384 priv" true
                (CCResult.is_ok (Jose.Jwk.of_priv_pem pem_priv_384));
              Alcotest.(check bool) "reparsed es384 pub" true
                (CCResult.is_ok (Jose.Jwk.of_pub_pem pem_pub_384));
              Alcotest.(check bool) "pub pem from priv 384" true
                (pem_pub_384 = pem_pub_from_priv_384);

              (* ES512 PEM *)
              let es512_priv = Jose.Jwk.of_priv_pem Fixtures.es512_test_priv |> CCResult.get_exn in
              let es512_pub = Jose.Jwk.pub_of_priv es512_priv in
              let pem_priv_512 = Jose.Jwk.to_priv_pem es512_priv |> CCResult.get_exn in
              let pem_pub_512 = Jose.Jwk.to_pub_pem es512_pub |> CCResult.get_exn in
              let pem_pub_from_priv_512 = Jose.Jwk.to_pub_pem es512_priv |> CCResult.get_exn in
              Alcotest.(check bool) "reparsed es512 priv" true
                (CCResult.is_ok (Jose.Jwk.of_priv_pem pem_priv_512));
              Alcotest.(check bool) "reparsed es512 pub" true
                (CCResult.is_ok (Jose.Jwk.of_pub_pem pem_pub_512));
              Alcotest.(check bool) "pub pem from priv 512" true
                (pem_pub_512 = pem_pub_from_priv_512);

              (* Unsupported PEM conversions *)
              let oct_jwk = Jose.Jwk.make_oct "secret" in
              Alcotest.(check bool) "Oct to_priv_pem is Unsupported_kty" true
                (Jose.Jwk.to_priv_pem oct_jwk = Error `Unsupported_kty);
              Alcotest.(check bool) "Oct to_pub_pem is Unsupported_kty" true
                (Jose.Jwk.to_pub_pem oct_jwk = Error `Unsupported_kty);

              let ed_p, _ = Mirage_crypto_ec.Ed25519.generate () in
              let ed_jwk =
                Jose.Jwk.Ed25519_priv
                  { alg = None; kty = `OKP; use = None; kid = None; key = ed_p }
              in
              Alcotest.(check bool) "Ed25519 to_priv_pem is Unsupported_kty" true
                (Jose.Jwk.to_priv_pem ed_jwk = Error `Unsupported_kty);
              Alcotest.(check bool) "Ed25519 to_pub_pem is Unsupported_kty" true
                (Jose.Jwk.to_pub_pem ed_jwk = Error `Unsupported_kty));
          Alcotest.test_case "JSON serialization and parsing for ES256, ES384, ES512" `Quick
            (fun () ->
              (* ES256 *)
              let es256_priv = Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn in
              let es256_pub = Jose.Jwk.pub_of_priv es256_priv in
              let priv_json_str = Jose.Jwk.to_priv_json_string es256_priv in
              let pub_json_str = Jose.Jwk.to_pub_json_string es256_pub in
              let pub_from_priv_str = Jose.Jwk.to_pub_json_string es256_priv in
              Alcotest.(check bool) "reparsed es256 priv json" true
                (CCResult.is_ok (Jose.Jwk.of_priv_json_string priv_json_str));
              Alcotest.(check bool) "reparsed es256 pub json" true
                (CCResult.is_ok (Jose.Jwk.of_pub_json_string pub_json_str));
              Alcotest.(check bool) "pub json equals pub from priv json" true
                (pub_json_str = pub_from_priv_str);

              (* ES384 *)
              let es384_p, _ = Mirage_crypto_ec.P384.Dsa.generate () in
              let es384_priv = Jose.Jwk.of_priv_x509 (`P384 es384_p) |> CCResult.get_exn in
              let es384_pub = Jose.Jwk.pub_of_priv es384_priv in
              let priv_json_str_384 = Jose.Jwk.to_priv_json_string es384_priv in
              let pub_json_str_384 = Jose.Jwk.to_pub_json_string es384_pub in
              let pub_from_priv_str_384 = Jose.Jwk.to_pub_json_string es384_priv in
              Alcotest.(check bool) "reparsed es384 priv json" true
                (CCResult.is_ok (Jose.Jwk.of_priv_json_string priv_json_str_384));
              Alcotest.(check bool) "reparsed es384 pub json" true
                (CCResult.is_ok (Jose.Jwk.of_pub_json_string pub_json_str_384));
              Alcotest.(check bool) "pub json equals pub from priv json 384" true
                (pub_json_str_384 = pub_from_priv_str_384);

              (* ES512 *)
              let es512_priv = Jose.Jwk.of_priv_pem Fixtures.es512_test_priv |> CCResult.get_exn in
              let es512_pub = Jose.Jwk.pub_of_priv es512_priv in
              let priv_json_str_512 = Jose.Jwk.to_priv_json_string es512_priv in
              let pub_json_str_512 = Jose.Jwk.to_pub_json_string es512_pub in
              let pub_from_priv_str_512 = Jose.Jwk.to_pub_json_string es512_priv in
              Alcotest.(check bool) "reparsed es512 priv json" true
                (CCResult.is_ok (Jose.Jwk.of_priv_json_string priv_json_str_512));
              Alcotest.(check bool) "reparsed es512 pub json" true
                (CCResult.is_ok (Jose.Jwk.of_pub_json_string pub_json_str_512));
              Alcotest.(check bool) "pub json equals pub from priv json 512" true
                (pub_json_str_512 = pub_from_priv_str_512));
          Alcotest.test_case "of_pub_json and of_priv_json error conditions" `Quick
            (fun () ->
              (* Malformed JSON *)
              Alcotest.(check bool) "of_pub_json_string malformed" true
                (CCResult.is_error (Jose.Jwk.of_pub_json_string "{bad json"));
              Alcotest.(check bool) "of_priv_json_string malformed" true
                (CCResult.is_error (Jose.Jwk.of_priv_json_string "{bad json"));

              (* Unsupported kty *)
              let unknown_kty_json = `Assoc [ ("kty", `String "UNKNOWN") ] in
              Alcotest.(check bool) "of_pub_json unknown kty" true
                (Jose.Jwk.of_pub_json unknown_kty_json = Error `Unsupported_kty);
              Alcotest.(check bool) "of_priv_json unknown kty" true
                (Jose.Jwk.of_priv_json unknown_kty_json = Error `Unsupported_kty);

              (* Unsupported EC curve *)
              let bad_crv_pub =
                `Assoc [ ("kty", `String "EC"); ("crv", `String "secp256k1"); ("x", `String "a"); ("y", `String "b") ]
              in
              Alcotest.(check bool) "of_pub_json bad EC crv" true
                (Jose.Jwk.of_pub_json bad_crv_pub = Error (`Msg "kty and alg doesn't match"));
              let bad_crv_priv =
                `Assoc [ ("kty", `String "EC"); ("crv", `String "secp256k1"); ("d", `String "a") ]
              in
              Alcotest.(check bool) "of_priv_json bad EC crv" true
                (Jose.Jwk.of_priv_json bad_crv_priv = Error (`Msg "kty and alg doesn't match"));

              (* Invalid base64 in EC coordinates (hits line 40 make_ESXXX_of_x_y error branch) *)
              let bad_b64_pub_ec =
                `Assoc [ ("kty", `String "EC"); ("crv", `String "P-256"); ("x", `String "???"); ("y", `String "???") ]
              in
              Alcotest.(check bool) "of_pub_json bad b64 EC" true
                (CCResult.is_error (Jose.Jwk.of_pub_json bad_b64_pub_ec));

              (* Invalid base64 in RSA pub (hits line 621 error branch) *)
              let bad_b64_pub_rsa =
                `Assoc [ ("kty", `String "RSA"); ("e", `String "???"); ("n", `String "???") ]
              in
              Alcotest.(check bool) "of_pub_json bad b64 RSA" true
                (CCResult.is_error (Jose.Jwk.of_pub_json bad_b64_pub_rsa));

              (* Invalid base64 in RSA priv (hits Utils.ml all8 error branch) *)
              let bad_b64_priv_rsa =
                `Assoc
                  [
                    ("kty", `String "RSA");
                    ("e", `String "AQAB");
                    ("n", `String "???");
                    ("d", `String "???");
                    ("p", `String "???");
                    ("q", `String "???");
                    ("dp", `String "???");
                    ("dq", `String "???");
                    ("qi", `String "???");
                  ]
              in
              Alcotest.(check bool) "of_priv_json bad b64 RSA priv" true
                (CCResult.is_error (Jose.Jwk.of_priv_json bad_b64_priv_rsa));

              (* Type errors in fields *)
              let type_err_rsa = `Assoc [ ("kty", `String "RSA"); ("n", `Int 123) ] in
              Alcotest.(check bool) "type error in RSA" true
                (CCResult.is_error (Jose.Jwk.of_pub_json type_err_rsa));
              let type_err_oct = `Assoc [ ("kty", `String "oct"); ("k", `Int 123) ] in
              Alcotest.(check bool) "type error in oct" true
                (CCResult.is_error (Jose.Jwk.of_pub_json type_err_oct));
              let type_err_ec = `Assoc [ ("kty", `String "EC"); ("crv", `Int 123) ] in
              Alcotest.(check bool) "type error in EC" true
                (CCResult.is_error (Jose.Jwk.of_pub_json type_err_ec));
              let type_err_okp = `Assoc [ ("kty", `String "OKP"); ("x", `Int 123) ] in
              Alcotest.(check bool) "type error in OKP" true
                (CCResult.is_error (Jose.Jwk.of_pub_json type_err_okp)));
          Alcotest.test_case "Private key thumbprints for EC keys" `Quick
            (fun () ->
              (* ES256 priv thumbprint *)
              let es256_priv = Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn in
              let es256_pub = Jose.Jwk.pub_of_priv es256_priv in
              let tp_priv_256 = Jose.Jwk.get_thumbprint `SHA256 es256_priv |> CCResult.get_exn in
              let tp_pub_256 = Jose.Jwk.get_thumbprint `SHA256 es256_pub |> CCResult.get_exn in
              check_string "ES256 priv/pub thumbprints match" tp_pub_256 tp_priv_256;

              (* ES384 priv thumbprint *)
              let es384_p, _ = Mirage_crypto_ec.P384.Dsa.generate () in
              let es384_priv = Jose.Jwk.of_priv_x509 (`P384 es384_p) |> CCResult.get_exn in
              let es384_pub = Jose.Jwk.pub_of_priv es384_priv in
              let tp_priv_384 = Jose.Jwk.get_thumbprint `SHA256 es384_priv |> CCResult.get_exn in
              let tp_pub_384 = Jose.Jwk.get_thumbprint `SHA256 es384_pub |> CCResult.get_exn in
              check_string "ES384 priv/pub thumbprints match" tp_pub_384 tp_priv_384;

              (* ES512 priv thumbprint *)
              let es512_priv = Jose.Jwk.of_priv_pem Fixtures.es512_test_priv |> CCResult.get_exn in
              let es512_pub = Jose.Jwk.pub_of_priv es512_priv in
              let tp_priv_512 = Jose.Jwk.get_thumbprint `SHA256 es512_priv |> CCResult.get_exn in
              let tp_pub_512 = Jose.Jwk.get_thumbprint `SHA256 es512_pub |> CCResult.get_exn in
              check_string "ES512 priv/pub thumbprints match" tp_pub_512 tp_priv_512);
          Alcotest.test_case "pub_of_priv on Oct returns Oct" `Quick (fun () ->
              let oct_priv = Jose.Jwk.make_oct "secret" in
              let oct_pub = Jose.Jwk.pub_of_priv oct_priv in
              check_string "Oct pub_of_priv preserves kid"
                (Jose.Jwk.get_kid oct_priv |> Option.value ~default:"")
                (Jose.Jwk.get_kid oct_pub |> Option.value ~default:""));
          Alcotest.test_case "of_priv_x509 and of_pub_x509 unsupported kty" `Quick
            (fun () ->
              let ed_p, ed_pub_raw = Mirage_crypto_ec.Ed25519.generate () in
              Alcotest.(check bool) "of_priv_x509 ED25519 unsupported" true
                (Jose.Jwk.of_priv_x509 (`ED25519 ed_p) = Error `Unsupported_kty);
              Alcotest.(check bool) "of_pub_x509 ED25519 unsupported" true
                (Jose.Jwk.of_pub_x509 (`ED25519 ed_pub_raw) = Error `Unsupported_kty));
          Alcotest.test_case "RSA alg and use inference in of_pub_json and of_priv_json" `Quick
            (fun () ->
              let rsa_priv_parsed =
                Jose.Jwk.of_priv_json_string Fixtures.private_jwk_string |> CCResult.get_exn
              in
              let rsa_pub_json = Jose.Jwk.to_pub_json rsa_priv_parsed in
              let rsa_priv_json = Jose.Jwk.to_priv_json rsa_priv_parsed in

              let strip_keys keys json =
                match json with
                | `Assoc l -> `Assoc (List.filter (fun (k, _) -> not (List.mem k keys)) l)
                | other -> other
              in

              (* RSA priv with alg only -> use inferred *)
              let priv_alg_only =
                `Assoc (("alg", `String "RS256") :: (strip_keys ["alg"; "use"] rsa_priv_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_priv_alg = Jose.Jwk.of_priv_json priv_alg_only |> CCResult.get_exn in
              Alcotest.(check bool) "inferred alg RS256" true (Jose.Jwk.get_alg parsed_priv_alg = Some `RS256);

              let priv_enc_only =
                `Assoc (("alg", `String "RSA-OAEP") :: (strip_keys ["alg"; "use"] rsa_priv_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_priv_enc = Jose.Jwk.of_priv_json priv_enc_only |> CCResult.get_exn in
              Alcotest.(check bool) "inferred use Enc" true (Jose.Jwk.get_alg parsed_priv_enc = Some `RSA_OAEP);

              (* RSA priv with use only -> alg inferred *)
              let priv_use_only =
                `Assoc (("use", `String "sig") :: (strip_keys ["alg"; "use"] rsa_priv_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_priv_use = Jose.Jwk.of_priv_json priv_use_only |> CCResult.get_exn in
              Alcotest.(check bool) "inferred alg RS256" true (Jose.Jwk.get_alg parsed_priv_use = Some `RS256);

              let priv_use_custom =
                `Assoc (("use", `String "custom") :: (strip_keys ["alg"; "use"] rsa_priv_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_priv_custom = Jose.Jwk.of_priv_json priv_use_custom |> CCResult.get_exn in
              Alcotest.(check bool) "inferred custom alg" true
                (Jose.Jwk.get_alg parsed_priv_custom = Some (`Unsupported "We don't know what to do with use: custom"));

              (* RSA pub with various algs and uses *)
              let pub_oaep =
                `Assoc (("alg", `String "RSA-OAEP") :: (strip_keys ["alg"; "use"] rsa_pub_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_pub_oaep = Jose.Jwk.of_pub_json pub_oaep |> CCResult.get_exn in
              Alcotest.(check bool) "pub inferred Enc" true (Jose.Jwk.get_alg parsed_pub_oaep = Some `RSA_OAEP);

              let pub_none =
                `Assoc (("alg", `String "none") :: (strip_keys ["alg"; "use"] rsa_pub_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_pub_none = Jose.Jwk.of_pub_json pub_none |> CCResult.get_exn in
              Alcotest.(check bool) "pub none" true (Jose.Jwk.get_alg parsed_pub_none = Some `None);

              let pub_custom_alg =
                `Assoc (("alg", `String "custom") :: (strip_keys ["alg"; "use"] rsa_pub_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_pub_custom = Jose.Jwk.of_pub_json pub_custom_alg |> CCResult.get_exn in
              Alcotest.(check bool) "pub custom" true (Jose.Jwk.get_alg parsed_pub_custom = Some (`Unsupported "custom"));

              let pub_use_custom =
                `Assoc (("use", `String "custom") :: (strip_keys ["alg"; "use"] rsa_pub_json |> Yojson.Safe.Util.to_assoc))
              in
              let parsed_pub_use_custom = Jose.Jwk.of_pub_json pub_use_custom |> CCResult.get_exn in
              Alcotest.(check bool) "pub use custom" true
                (Jose.Jwk.get_alg parsed_pub_use_custom = Some (`Unsupported "We don't know what to do with use: custom")));
          Alcotest.test_case "of_priv_json type errors" `Quick (fun () ->
              let type_err_rsa_priv = `Assoc [ ("kty", `String "RSA"); ("d", `Int 123) ] in
              Alcotest.(check bool) "priv rsa type err" true
                (CCResult.is_error (Jose.Jwk.of_priv_json type_err_rsa_priv));
              let type_err_ec_priv = `Assoc [ ("kty", `String "EC"); ("d", `Int 123) ] in
              Alcotest.(check bool) "priv ec type err" true
                (CCResult.is_error (Jose.Jwk.of_priv_json type_err_ec_priv));
              let type_err_okp_priv = `Assoc [ ("kty", `String "OKP"); ("d", `Int 123) ] in
              Alcotest.(check bool) "priv okp type err" true
                (CCResult.is_error (Jose.Jwk.of_priv_json type_err_okp_priv)));
        ] );
    ]

let jwk_suite = jwk_suite
