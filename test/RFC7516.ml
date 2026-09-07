(* Tests for RFC 7516 (JSON Web Encryption) and related JWA RFC 7518 algorithms *)
let () = Mirage_crypto_rng_unix.use_default ()

open Helpers

let rsa_priv_jwk =
  Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string |> CCResult.get_exn

(* Appendix A.1: RSA-OAEP and AES GCM *)
let rsa_priv_json_a1 =
  {|{"kty":"RSA",
 "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
 "e":"AQAB",
 "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
 "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
 "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
 "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
 "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
 "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
}|}

let jwe_compact_a1 =
  "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
  ^ "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg."
  ^ "48V1_ALb6US04U3b."
  ^ "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A."
  ^ "XFBoMYUZodetZdvTiFvSkQ"

let plaintext_a1 =
  "The true sign of intelligence is not knowledge but imagination."

(* Appendix A.2: RSA1_5 and AES_128_CBC_HMAC_SHA_256 *)
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

let jwe_compact_a2 =
  "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
  ^ "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A."
  ^ "AxY8DCtDaGlsbGljb3RoZQ."
  ^ "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
  ^ "9hH0vgRfYgPnAHOd8stkvw"

let plaintext_a2 = "Live long and prosper."

let jwe_tests =
  ( "RFC7516",
    [
      Alcotest.test_case "A.1: Decrypt RSA-OAEP + A256GCM" `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_json_a1 |> CCResult.get_exn
          in
          let decrypted = Jose.Jwe.decrypt ~jwk jwe_compact_a1 in
          Alcotest.(check bool)
            "A.1 JWE decrypts successfully" true (CCResult.is_ok decrypted);
          let jwe = CCResult.get_exn decrypted in
          check_string "Payload matches" plaintext_a1 jwe.payload;
          Alcotest.(check bool)
            "Header alg is RSA-OAEP" true
            (jwe.header.alg = `RSA_OAEP);
          Alcotest.(check bool)
            "Header enc is A256GCM" true
            (jwe.header.enc = Some `A256GCM);
          check_string "IV matches" "48V1_ALb6US04U3b"
            (url_encode_string jwe.iv);
          (* Roundtrip: encrypt and decrypt freshly generated JWE *)
          let re_encrypted =
            Jose.Jwe.encrypt ~jwk jwe
            |> CCResult.flat_map (Jose.Jwe.decrypt ~jwk)
          in
          Alcotest.(check bool)
            "A.1 roundtrip succeeds" true
            (CCResult.is_ok re_encrypted);
          check_string "A.1 roundtrip payload matches" plaintext_a1
            (CCResult.get_exn re_encrypted).payload);
      Alcotest.test_case "A.2: Decrypt RSA1_5 + A128CBC-HS256" `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_json_a2 |> CCResult.get_exn
          in
          let decrypted = Jose.Jwe.decrypt ~jwk jwe_compact_a2 in
          Alcotest.(check bool)
            "A.2 JWE decrypts successfully" true (CCResult.is_ok decrypted);
          let jwe = CCResult.get_exn decrypted in
          check_string "Payload matches" plaintext_a2 jwe.payload;
          Alcotest.(check bool)
            "Header alg is RSA1_5" true
            (jwe.header.alg = `RSA1_5);
          Alcotest.(check bool)
            "Header enc is A128CBC-HS256" true
            (jwe.header.enc = Some `A128CBC_HS256);
          check_string "IV matches" "AxY8DCtDaGlsbGljb3RoZQ"
            (url_encode_string jwe.iv);
          (* Roundtrip: encrypt and decrypt freshly generated JWE *)
          let re_encrypted =
            Jose.Jwe.encrypt ~jwk jwe
            |> CCResult.flat_map (Jose.Jwe.decrypt ~jwk)
          in
          Alcotest.(check bool)
            "A.2 roundtrip succeeds" true
            (CCResult.is_ok re_encrypted);
          check_string "A.2 roundtrip payload matches" plaintext_a2
            (CCResult.get_exn re_encrypted).payload);
      Alcotest.test_case "IV length is determined by enc (CBC vs GCM)" `Quick
        (fun () ->
          (* RSA-OAEP paired with CBC must use 16 bytes *)
          let header_cbc =
            Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A128CBC_HS256
              rsa_priv_jwk
          in
          let jwe_cbc =
            Jose.Jwe.make ~header:header_cbc "secret message"
            |> CCResult.get_exn
          in
          Alcotest.(check int)
            "CBC IV length must be 16 bytes" 16 (String.length jwe_cbc.iv);

          (* RSA1_5 paired with GCM must use 12 bytes (96 bits) *)
          let header_gcm =
            Jose.Header.make_header ~alg:`RSA1_5 ~enc:`A256GCM rsa_priv_jwk
          in
          let jwe_gcm =
            Jose.Jwe.make ~header:header_gcm "secret message"
            |> CCResult.get_exn
          in
          Alcotest.(check int)
            "GCM IV length must be 12 bytes" 12 (String.length jwe_gcm.iv));
      Alcotest.test_case
        "PKCS#7 unpadding gracefully handles corrupted padding without \
         exception"
        `Quick (fun () ->
          let header =
            Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A128CBC_HS256
              rsa_priv_jwk
          in
          let jwe =
            Jose.Jwe.make ~header "test payload"
            |> CCResult.get_exn
            |> Jose.Jwe.encrypt ~jwk:rsa_priv_jwk
            |> CCResult.get_exn
          in
          (* Tamper with ciphertext by corrupting bytes *)
          let segs = String.split_on_char '.' jwe in
          let corrupted_jwe =
            String.concat "."
              [
                List.nth segs 0;
                List.nth segs 1;
                List.nth segs 2;
                url_encode_string "\x00\x00\x00\x00\x00\x00\x00\x00";
                List.nth segs 4;
              ]
          in
          let raised =
            try
              let _ = Jose.Jwe.decrypt ~jwk:rsa_priv_jwk corrupted_jwe in
              false
            with Invalid_argument _ -> true
          in
          Alcotest.(check bool)
            "decrypt must return Result.Error and not throw Invalid_argument \
             exception"
            false raised);
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7516" [ jwe_tests ]
