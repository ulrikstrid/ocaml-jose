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
                Jose.Jwk.of_pub_json_string pub_string |> CCResult.get_exn
              in
              check_result_string "Creates the correct thumbprint"
                (Ok "nBBpbUsITZuECZH0WpBqPH4HKwYV3Tx2KDVyNfwvOkU")
              @@ Result.map url_encode_string
              @@ Jose.Jwk.get_thumbprint `SHA256 pub_jwk);
          Alcotest.test_case "make_* functions support ?alg and ?use" `Quick
            (fun () ->
              let oct_jwk =
                Jose.Jwk.make_oct ~use:`Enc ~alg:`A128KW "0123456789abcdef"
              in
              Alcotest.(check (option string))
                "oct alg is A128KW" (Some "A128KW")
                (Jose.Jwk.get_alg oct_jwk |> Option.map Jose.Jwa.alg_to_string);

              let priv_es256 = Mirage_crypto_ec.P256.Dsa.generate () |> fst in
              let pub_es256 =
                Mirage_crypto_ec.P256.Dsa.pub_of_priv priv_es256
              in
              let es_jwk =
                Jose.Jwk.make_priv_es256 ~use:`Enc ~alg:`ECDH_ES priv_es256
              in
              Alcotest.(check (option string))
                "es256 alg is ECDH-ES" (Some "ECDH-ES")
                (Jose.Jwk.get_alg es_jwk |> Option.map Jose.Jwa.alg_to_string);
              let es_pub_jwk =
                Jose.Jwk.make_pub_es256 ~use:`Enc ~alg:`ECDH_ES pub_es256
              in
              Alcotest.(check (option string))
                "es256 pub alg is ECDH-ES" (Some "ECDH-ES")
                (Jose.Jwk.get_alg es_pub_jwk
                |> Option.map Jose.Jwa.alg_to_string);

              let priv_es384 = Mirage_crypto_ec.P384.Dsa.generate () |> fst in
              let pub_es384 =
                Mirage_crypto_ec.P384.Dsa.pub_of_priv priv_es384
              in
              let es384_jwk = Jose.Jwk.make_priv_es384 priv_es384 in
              Alcotest.(check (option string))
                "es384 default alg is ES384" (Some "ES384")
                (Jose.Jwk.get_alg es384_jwk |> Option.map Jose.Jwa.alg_to_string);
              let es384_pub_jwk = Jose.Jwk.make_pub_es384 pub_es384 in
              Alcotest.(check (option string))
                "es384 pub default alg is ES384" (Some "ES384")
                (Jose.Jwk.get_alg es384_pub_jwk
                |> Option.map Jose.Jwa.alg_to_string);

              let priv_es512 = Mirage_crypto_ec.P521.Dsa.generate () |> fst in
              let pub_es512 =
                Mirage_crypto_ec.P521.Dsa.pub_of_priv priv_es512
              in
              let es512_jwk = Jose.Jwk.make_priv_es512 priv_es512 in
              Alcotest.(check (option string))
                "es512 default alg is ES512" (Some "ES512")
                (Jose.Jwk.get_alg es512_jwk |> Option.map Jose.Jwa.alg_to_string);
              let es512_pub_jwk = Jose.Jwk.make_pub_es512 pub_es512 in
              Alcotest.(check (option string))
                "es512 pub default alg is ES512" (Some "ES512")
                (Jose.Jwk.get_alg es512_pub_jwk
                |> Option.map Jose.Jwa.alg_to_string);

              let priv_ed = Mirage_crypto_ec.Ed25519.generate () |> fst in
              let pub_ed = Mirage_crypto_ec.Ed25519.pub_of_priv priv_ed in
              let ed_jwk =
                Jose.Jwk.make_priv_ed25519 ~use:`Sig ~alg:`EdDSA priv_ed
              in
              Alcotest.(check (option string))
                "ed25519 alg is EdDSA" (Some "EdDSA")
                (Jose.Jwk.get_alg ed_jwk |> Option.map Jose.Jwa.alg_to_string);
              let ed_pub_jwk =
                Jose.Jwk.make_pub_ed25519 ~use:`Sig ~alg:`Ed25519 pub_ed
              in
              Alcotest.(check (option string))
                "ed25519 pub alg is Ed25519" (Some "Ed25519")
                (Jose.Jwk.get_alg ed_pub_jwk
                |> Option.map Jose.Jwa.alg_to_string);

              let ed_pem = Jose.Jwk.to_pub_pem ed_pub_jwk |> CCResult.get_exn in
              let ed_reimported =
                Jose.Jwk.of_pub_pem ed_pem |> CCResult.get_exn
              in
              Alcotest.(check (option string))
                "ed25519 kid roundtrip matches"
                (Jose.Jwk.get_kid ed_pub_jwk)
                (Jose.Jwk.get_kid ed_reimported));
          Alcotest.test_case "use_of_alg and automatic use inference in make_*"
            `Quick (fun () ->
              Alcotest.(check (option string))
                "HS256 -> sig" (Some "sig")
                (Jose.Jwa.use_of_alg `HS256 |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "RS256 -> sig" (Some "sig")
                (Jose.Jwa.use_of_alg `RS256 |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "ES256 -> sig" (Some "sig")
                (Jose.Jwa.use_of_alg `ES256 |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "ES384 -> sig" (Some "sig")
                (Jose.Jwa.use_of_alg `ES384 |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "ES512 -> sig" (Some "sig")
                (Jose.Jwa.use_of_alg `ES512 |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "EdDSA -> sig" (Some "sig")
                (Jose.Jwa.use_of_alg `EdDSA |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "Ed25519 -> sig" (Some "sig")
                (Jose.Jwa.use_of_alg `Ed25519
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "RSA_OAEP -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `RSA_OAEP
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "RSA1_5 -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `RSA1_5
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "Dir -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `Dir |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "A128KW -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `A128KW
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "A256KW -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `A256KW
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "ECDH_ES -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `ECDH_ES
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "ECDH_ES_A128KW -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `ECDH_ES_A128KW
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "ECDH_ES_A256KW -> enc" (Some "enc")
                (Jose.Jwa.use_of_alg `ECDH_ES_A256KW
                |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "None -> none" None
                (Jose.Jwa.use_of_alg `None |> Option.map Jose.Jwa.use_to_string);
              Alcotest.(check (option string))
                "Unsupported -> none" None
                (Jose.Jwa.use_of_alg (`Unsupported "FOO")
                |> Option.map Jose.Jwa.use_to_string);

              let get_use (type a) (jwk : a Jose.Jwk.t) =
                match jwk with
                | Jose.Jwk.Oct oct -> oct.use
                | Jose.Jwk.Rsa_priv rsa -> rsa.use
                | Jose.Jwk.Rsa_pub rsa -> rsa.use
                | Jose.Jwk.Es256_priv es -> es.use
                | Jose.Jwk.Es256_pub es -> es.use
                | Jose.Jwk.Es384_priv es -> es.use
                | Jose.Jwk.Es384_pub es -> es.use
                | Jose.Jwk.Es512_priv es -> es.use
                | Jose.Jwk.Es512_pub es -> es.use
                | Jose.Jwk.Ed25519_priv ed -> ed.use
                | Jose.Jwk.Ed25519_pub ed -> ed.use
              in

              let oct_default = Jose.Jwk.make_oct "secret" in
              Alcotest.(check (option string))
                "make_oct default use is Sig" (Some "sig")
                (get_use oct_default |> Option.map Jose.Jwa.use_to_string);

              let oct_enc = Jose.Jwk.make_oct ~alg:`A128KW "secret" in
              Alcotest.(check (option string))
                "make_oct with A128KW infers Enc" (Some "enc")
                (get_use oct_enc |> Option.map Jose.Jwa.use_to_string);

              let rsa_priv = Mirage_crypto_pk.Rsa.generate ~bits:1024 () in
              let rsa_pub = Mirage_crypto_pk.Rsa.pub_of_priv rsa_priv in
              let rsa_priv_none = Jose.Jwk.make_priv_rsa rsa_priv in
              Alcotest.(check (option string))
                "make_priv_rsa without alg/use has use = None" None
                (get_use rsa_priv_none |> Option.map Jose.Jwa.use_to_string);

              let rsa_priv_sig = Jose.Jwk.make_priv_rsa ~alg:`RS256 rsa_priv in
              Alcotest.(check (option string))
                "make_priv_rsa ~alg:`RS256 infers Sig" (Some "sig")
                (get_use rsa_priv_sig |> Option.map Jose.Jwa.use_to_string);

              let rsa_pub_enc = Jose.Jwk.make_pub_rsa ~alg:`RSA_OAEP rsa_pub in
              Alcotest.(check (option string))
                "make_pub_rsa ~alg:`RSA_OAEP infers Enc" (Some "enc")
                (get_use rsa_pub_enc |> Option.map Jose.Jwa.use_to_string);

              let priv_es256 = Mirage_crypto_ec.P256.Dsa.generate () |> fst in
              let es256_priv_default = Jose.Jwk.make_priv_es256 priv_es256 in
              Alcotest.(check (option string))
                "make_priv_es256 default use is Sig" (Some "sig")
                (get_use es256_priv_default |> Option.map Jose.Jwa.use_to_string);

              let es256_enc =
                Jose.Jwk.make_priv_es256 ~alg:`ECDH_ES priv_es256
              in
              Alcotest.(check (option string))
                "make_priv_es256 ~alg:`ECDH_ES infers Enc" (Some "enc")
                (get_use es256_enc |> Option.map Jose.Jwa.use_to_string);

              let es256_override =
                Jose.Jwk.make_priv_es256 ~use:`Sig ~alg:`ECDH_ES priv_es256
              in
              Alcotest.(check (option string))
                "explicit ?use takes precedence over alg" (Some "sig")
                (get_use es256_override |> Option.map Jose.Jwa.use_to_string);

              let priv_ed = Mirage_crypto_ec.Ed25519.generate () |> fst in
              let pub_ed = Mirage_crypto_ec.Ed25519.pub_of_priv priv_ed in
              let ed_priv_default = Jose.Jwk.make_priv_ed25519 priv_ed in
              Alcotest.(check (option string))
                "make_priv_ed25519 default use is Sig" (Some "sig")
                (get_use ed_priv_default |> Option.map Jose.Jwa.use_to_string);
              let ed_pub_default = Jose.Jwk.make_pub_ed25519 pub_ed in
              Alcotest.(check (option string))
                "make_pub_ed25519 default use is Sig" (Some "sig")
                (get_use ed_pub_default |> Option.map Jose.Jwa.use_to_string));
        ] );
    ]

let jwk_suite = jwk_suite
