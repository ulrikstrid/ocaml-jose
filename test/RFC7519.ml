(* Tests for RFC 7519 (JSON Web Token) *)
open Helpers

let oct_priv_json =
  {|{"kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }|}

let rsa_priv_json =
  {|{"kty":"RSA",
     "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
     "e":"AQAB",
     "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
     "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
     "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
     "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
     "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
     "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
    }|}

let ec_priv_json_es256 =
  {|{"kty":"EC",
     "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d",
     "crv":"P-256",
     "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
     "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
     "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
    }|}

let rsa_priv_json_a2 =
  {|{"kty":"RSA",
     "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
     "e":"AQAB",
     "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
     "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
     "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
     "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
     "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
     "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
    }|}

let rfc7519_jwt_str =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
  ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
  ^ "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

let rfc7519_unsecured_jwt_str =
  "eyJhbGciOiJub25lIn0."
  ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

let rfc7515_a2_rs256_jwt_str =
  "eyJhbGciOiJSUzI1NiJ9."
  ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
  ^ "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

let rfc7515_a3_es256_jwt_str =
  "eyJhbGciOiJFUzI1NiJ9."
  ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
  ^ "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

let rfc7519_encrypted_jwt_str =
  "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
  ^ "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtMoNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLGTkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26imasOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a1rZgN5TiysnmzTROF869lQ."
  ^ "AxY8DCtDaGlsbGljb3RoZQ."
  ^ "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaMHDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8."
  ^ "fiK51VwhsxJ-siBMR-YFiA"

let rfc7519_nested_jwt_str =
  "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0."
  ^ "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_MqewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYEb9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvhDuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6DYyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsqJGTO_z3Wfo5zsqwkxruxwA."
  ^ "UmVkbW9uZCBXQSA5ODA1Mg."
  ^ "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTBBLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZYKw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvrZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb28Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpEl8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11UzBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."
  ^ "AVO9iT5AV4CzvDJCdhSFlQ"

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
            "header alg is HS256" true (jwt.header.alg = `HS256));
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
      Alcotest.test_case
        "4.1.4: Token with now == exp fails (current time MUST be before exp)"
        `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string oct_priv_json |> CCResult.get_exn
          in
          let now_exact_exp =
            Ptime.of_float_s 1300819380.0 |> CCOption.get_exn_or "exact exp"
          in
          let res =
            Jose.Jwt.of_string ~jwk ~now:now_exact_exp rfc7519_jwt_str
          in
          Alcotest.(check bool)
            "fails when now == exp" true
            (match res with Error `Expired -> true | _ -> false));
      Alcotest.test_case "6.1: Parse unsecured JWT with unsafe_of_string" `Quick
        (fun () ->
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
            "header alg is None" true (jwt.header.alg = `None));
      Alcotest.test_case "8: Recommended RS256 signature validation" `Quick
        (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_json |> CCResult.get_exn
          in
          let now_valid =
            Ptime.of_float_s 1300819300.0 |> CCOption.get_exn_or "valid time"
          in
          let jwt =
            Jose.Jwt.of_string ~jwk ~now:now_valid rfc7515_a2_rs256_jwt_str
            |> CCResult.get_exn
          in
          check_option_string "iss claim is joe" "joe"
            (Jose.Jwt.get_string_claim jwt "iss");
          check_option_int "exp claim is 1300819380" 1300819380
            (Jose.Jwt.get_int_claim jwt "exp");
          Alcotest.(check bool)
            "header alg is RS256" true (jwt.header.alg = `RS256));
      Alcotest.test_case "8: Recommended ES256 signature validation" `Quick
        (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string ec_priv_json_es256 |> CCResult.get_exn
          in
          let now_valid =
            Ptime.of_float_s 1300819300.0 |> CCOption.get_exn_or "valid time"
          in
          let jwt =
            Jose.Jwt.of_string ~jwk ~now:now_valid rfc7515_a3_es256_jwt_str
            |> CCResult.get_exn
          in
          check_option_string "iss claim is joe" "joe"
            (Jose.Jwt.get_string_claim jwt "iss");
          check_option_int "exp claim is 1300819380" 1300819380
            (Jose.Jwt.get_int_claim jwt "exp");
          Alcotest.(check bool)
            "header alg is ES256" true (jwt.header.alg = `ES256));
      Alcotest.test_case "A.1: Decrypt Encrypted JWT (RSA1_5 + A128CBC-HS256)"
        `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_json_a2 |> CCResult.get_exn
          in
          let jwe =
            Jose.Jwe.decrypt ~jwk rfc7519_encrypted_jwt_str |> CCResult.get_exn
          in
          Alcotest.(check bool)
            "header alg is RSA1_5" true (jwe.header.alg = `RSA1_5);
          Alcotest.(check bool)
            "header enc is A128CBC_HS256" true
            (jwe.header.enc = Some `A128CBC_HS256);
          let claims_json = Yojson.Safe.from_string jwe.payload in
          let iss =
            Yojson.Safe.Util.member "iss" claims_json
            |> Yojson.Safe.Util.to_string_option
          in
          let exp =
            Yojson.Safe.Util.member "exp" claims_json
            |> Yojson.Safe.Util.to_int_option
          in
          check_option_string "decrypted iss claim is joe" "joe" iss;
          check_option_int "decrypted exp claim is 1300819380" 1300819380 exp);
      Alcotest.test_case "A.2: Decrypt and validate Nested JWT (cty: JWT)"
        `Quick (fun () ->
          (* Outer decryption with RSA key from RFC 7516 A.2 *)
          let jwe_jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_json_a2 |> CCResult.get_exn
          in
          let jwe =
            Jose.Jwe.decrypt ~jwk:jwe_jwk rfc7519_nested_jwt_str
            |> CCResult.get_exn
          in
          Alcotest.(check (option string))
            "header cty is JWT" (Some "JWT") jwe.header.cty;
          (* Inner signature verification with RSA key from RFC 7515 A.2 *)
          let jws_jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_json |> CCResult.get_exn
          in
          let now_valid =
            Ptime.of_float_s 1300819300.0 |> CCOption.get_exn_or "valid time"
          in
          let inner_jwt =
            Jose.Jwt.of_string ~jwk:jws_jwk ~now:now_valid jwe.payload
            |> CCResult.get_exn
          in
          check_option_string "inner iss claim is joe" "joe"
            (Jose.Jwt.get_string_claim inner_jwt "iss");
          check_option_int "inner exp claim is 1300819380" 1300819380
            (Jose.Jwt.get_int_claim inner_jwt "exp");
          Alcotest.(check bool)
            "inner alg is RS256" true
            (inner_jwt.header.alg = `RS256));
      Alcotest.test_case "7.2: Reject malformed JWT (missing dot delimiter)"
        `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string oct_priv_json |> CCResult.get_exn
          in
          let now =
            Ptime.of_float_s 1300819300.0 |> CCOption.get_exn_or "valid time"
          in
          let res =
            Jose.Jwt.of_string ~jwk ~now "nodotsinthiscompactrepresentation"
          in
          Alcotest.(check bool)
            "rejects missing period" true (CCResult.is_error res));
      Alcotest.test_case "7.2: Reject JWT with invalid signature" `Quick
        (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string oct_priv_json |> CCResult.get_exn
          in
          let now =
            Ptime.of_float_s 1300819300.0 |> CCOption.get_exn_or "valid time"
          in
          let tampered_jwt =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            ^ "eyJpc3MiOiJhbGljZSIsImV4cCI6MTMwMDgxOTM4MH0."
            ^ "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
          in
          let res = Jose.Jwt.of_string ~jwk ~now tampered_jwt in
          Alcotest.(check bool)
            "rejects tampered signature" true (CCResult.is_error res));
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7519" [ jwt_tests ]
