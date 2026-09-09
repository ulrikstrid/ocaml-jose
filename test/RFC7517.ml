(* Tests for RFC 7517 (JSON Web Key) *)

let jwks_public_json =
  {|{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"},

         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }|}

let ec_priv_json =
  {|{"kty":"EC",
     "crv":"P-256",
     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
     "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
     "use":"enc",
     "kid":"1"}|}

let rsa_priv_json =
  {|{"kty":"RSA",
     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB",
     "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
     "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
     "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
     "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
     "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
     "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
     "alg":"RS256",
     "kid":"2011-04-29"}|}

let oct_kw_json =
  {|{"kty":"oct",
     "alg":"A128KW",
     "k":"GawgguFyGrWKav7AX4VKUg"}|}

let oct_hmac_json =
  {|{"kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
     "kid":"HMAC key used in JWS spec Appendix A.1 example"}|}

let jwk_tests =
  ( "RFC7517",
    [
      Alcotest.test_case "A.1: Parse JWK Set with Public EC and RSA keys" `Quick
        (fun () ->
          let jwks = Jose.Jwks.of_string jwks_public_json in
          Alcotest.(check int) "contains 2 keys" 2 (List.length jwks.keys);
          let ec_key = Jose.Jwks.find_key jwks "1" in
          Alcotest.(check bool)
            "found EC key by kid" true (Option.is_some ec_key);
          let rsa_key = Jose.Jwks.find_key jwks "2011-04-29" in
          Alcotest.(check bool)
            "found RSA key by kid" true (Option.is_some rsa_key));
      Alcotest.test_case "A.2: Parse EC P-256 Private Key" `Quick (fun () ->
          let jwk = Jose.Jwk.of_priv_json_string ec_priv_json in
          Alcotest.(check bool) "parses successfully" true (CCResult.is_ok jwk);
          let key = CCResult.get_exn jwk in
          Alcotest.(check bool) "kty is EC" true (Jose.Jwk.get_kty key = `EC);
          Alcotest.(check (option string))
            "kid matches" (Some "1") (Jose.Jwk.get_kid key));
      Alcotest.test_case "A.2: Parse RSA Private Key" `Quick (fun () ->
          let jwk = Jose.Jwk.of_priv_json_string rsa_priv_json in
          Alcotest.(check bool) "parses successfully" true (CCResult.is_ok jwk);
          let key = CCResult.get_exn jwk in
          Alcotest.(check bool) "kty is RSA" true (Jose.Jwk.get_kty key = `RSA);
          Alcotest.(check (option string))
            "kid matches" (Some "2011-04-29") (Jose.Jwk.get_kid key);
          let pub = Jose.Jwk.pub_of_priv key in
          Alcotest.(check bool)
            "pub_of_priv produces RSA" true
            (Jose.Jwk.get_kty pub = `RSA));
      Alcotest.test_case "A.3: Parse Symmetric Keys" `Quick (fun () ->
          let kw_jwk = Jose.Jwk.of_priv_json_string oct_kw_json in
          Alcotest.(check bool) "parses A128KW key" true (CCResult.is_ok kw_jwk);
          let hmac_jwk = Jose.Jwk.of_priv_json_string oct_hmac_json in
          Alcotest.(check bool) "parses HMAC key" true (CCResult.is_ok hmac_jwk);
          let hmac_key = CCResult.get_exn hmac_jwk in
          Alcotest.(check (option string))
            "HMAC kid matches"
            (Some "HMAC key used in JWS spec Appendix A.1 example")
            (Jose.Jwk.get_kid hmac_key));
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7517" [ jwk_tests ]
