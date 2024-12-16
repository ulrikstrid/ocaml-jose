(* These tests are based on rfc7515, https://tools.ietf.org/html/rfc7515 *)

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

let ec_priv_json_es512 =
  {|{"kty":"EC",
"crv":"P-521",
"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
}|}

(* The real value has \r\n and I can't make that happen *)
let payload_to_same payload =
  Yojson.Safe.from_string payload |> Yojson.Safe.to_string

let payload_str =
  {|{"iss":"joe",
"exp":1300819380,
"http://example.com/is_root":true}|}
  |> payload_to_same

let a_4_jws =
  {|eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AWflgP1EaMjD8wn0_zbfv-ig7HqR_fIPutaspBmLdEA-4jq_lJSiXVScImGj9H15HwnQCV9rEqz_1IY7L07REF7rAGbY03ZbfpKy8sFRybi12kMjsgU8vGKHJPZl6BT9G930CnEfL7MpSJiZEpxO-CeMyQQFOxPvVh4N6n20NSK9Tlho|}

open Helpers

let jws_tests =
  ( "RFC7515",
    [
      Alcotest.test_case "A.1" `Quick (fun () ->
          let expected_str =
            {|eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk|}
          in
          let jwk =
            Jose.Jwk.of_priv_json_string oct_priv_json |> CCResult.get_exn
          in
          Jose.Jws.of_string expected_str
          |> CCResult.flat_map (Jose.Jws.validate ~jwk)
          |> CCResult.map (fun (jws : Jose.Jws.t) ->
                 payload_to_same jws.payload)
          |> check_result_string "Validated payload is correct" (Ok payload_str));
      Alcotest.test_case "A.2" `Quick (fun () ->
          let expected_str =
            {|eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw|}
          in
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_json |> CCResult.get_exn
          in
          Jose.Jws.of_string expected_str
          |> CCResult.flat_map (Jose.Jws.validate ~jwk)
          |> CCResult.map (fun (jws : Jose.Jws.t) ->
                 payload_to_same jws.payload)
          |> check_result_string "Validated payload is correct" (Ok payload_str));
      Alcotest.test_case "A.3" `Quick (fun () ->
          let expected_str =
            {|eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q|}
          in
          let jwk =
            Jose.Jwk.of_priv_json_string ec_priv_json_es256 |> CCResult.get_exn
          in
          Jose.Jws.of_string expected_str
          |> CCResult.flat_map (Jose.Jws.validate ~jwk)
          |> CCResult.map (fun (jws : Jose.Jws.t) ->
                 payload_to_same jws.payload)
          |> check_result_string "Validated payload is correct" (Ok payload_str));
      Alcotest.test_case "A.4 - validate" `Quick (fun () ->
          let expected_str = a_4_jws in
          let jwk =
            Jose.Jwk.of_priv_json_string ec_priv_json_es512 |> CCResult.get_exn
          in
          Jose.Jws.of_string expected_str
          |> CCResult.flat_map (Jose.Jws.validate ~jwk)
          |> CCResult.map (fun (jws : Jose.Jws.t) -> jws.payload)
          |> check_result_string "Validated payload is correct" (Ok "Payload"));
      Alcotest.test_case "A.4 - recreate JWS" `Quick (fun () ->
          let expected_str = a_4_jws in
          let jwk =
            Jose.Jwk.of_priv_json_string ec_priv_json_es512 |> CCResult.get_exn
          in
          let header =
            Jose.Header.
              {
                alg = `ES512;
                jwk = None;
                kid = None;
                x5t = None;
                x5t256 = None;
                typ = None;
                cty = None;
                enc = None;
                extra = [];
              }
          in
          Jose.Jws.sign ~header ~payload:"Payload" jwk
          |> CCResult.map Jose.Jws.to_string
          |> check_result_string "Validated JWS is same" (Ok expected_str));
      (* We currently do not support `none` *)
      Alcotest.test_case "A.5" `Quick (fun () ->
          let expected_str =
            {|eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.|}
          in
          let jwk =
            Jose.Jwk.of_priv_json_string ec_priv_json_es256 |> CCResult.get_exn
          in
          Jose.Jws.of_string expected_str
          |> CCResult.flat_map (Jose.Jws.validate ~jwk)
          |> CCResult.map (fun (jws : Jose.Jws.t) ->
                 payload_to_same jws.payload)
          |> check_result_string "Validated payload is correct"
               (Error (`Msg "alg not supported for signing")));
      (* A.6 uses multiple signatures which we don't support yet *)
      Alcotest.test_case "A.7" `Quick (fun () ->
          let header =
            Jose.Header.
              {
                alg = `ES256;
                jwk = None;
                kid = None;
                x5t = None;
                x5t256 = None;
                typ = None;
                cty = None;
                enc = None;
                extra = [];
              }
          in
          let jwk =
            Jose.Jwk.of_priv_json_string ec_priv_json_es256 |> CCResult.get_exn
          in
          Jose.Jws.sign ~header ~payload:payload_str jwk
          |> CCResult.map (Jose.Jws.to_string ~serialization:`Flattened)
          |> check_result_string "Validated payload is correct"
               (* We currently don't have a notion of Unprotected Headers Values so this is not exactly correct*)
               (Ok
                  {|{"payload":"eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","signature":"4XSeJsUDLhZisF7Vhx7iYI_q9x7a3Mk8-wsj-jpf39DRe-bDEt-w7UlN1xwfpiouuoGssgJKAT9GwEeORjzuIg"}|}));
    ] )

(* Begin tests *)
let rfc_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7515" [ jws_tests ]

let suite = rfc_suite
