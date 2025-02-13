let () = Mirage_crypto_rng_unix.use_default ()

open Helpers

(* These values are borrowed from the `ocaml-letsencrypt` test suite
   https://github.com/mmaker/ocaml-letsencrypt *)
let testkey_pem =
  "\n\
   -----BEGIN PRIVATE KEY-----\n\
   MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjGBnd5E+TChG/\n\
   Lup5FRuYwN7RX7Ef15Yt27SKF54uWuYPaapZd8/0h5IoCluffiDxO4BL2DnOGrwQ\n\
   tDeSaOv4pXzoYAyAjpUBwaWrdCvOlMJ//fQBvv7NrCt9FoU41rUfATM9jUoecZWT\n\
   ElzzmA2TBgj1JjZEde2+WffOznAhM2t2iyoRd5oiRVgESFuE27nimneTGjpO5YuL\n\
   17qld5Z60TCaUHC1ZmU+iJvaPdPEsGSwpl+jIXJ6TfzSYeAkC6ZD8jZ+OP3z/3ua\n\
   TeKE5jgCBV0IOPXP8YKhmQblGrudsIbKizIpbINfTRmz6c2pWGgt4i9cLiedZ0kx\n\
   nquiDHJBAgMBAAECggEABaFh98xKtEe0QbAXOGYPc3m5tIl5teNFmhC30NIt1fKj\n\
   QFfTdUkpDuQjGarLE4DgLnb2EvtTEJL9XXEobRD8o8Mvnf/Oo4vVcjATzFTSprot\n\
   udhpKbdrcBxADkeGCU8aecCw/WpQv4E7rwQuKYx4LrBgPbrDLu6ZFMZ8hEQ+R7Zn\n\
   j0jWswOZEwM5xNHZ8RlwP4xsyFChvBR43lymHwDwQegd7ukbY0OcwXZ+2sxcKltr\n\
   LBZKKFPzMugKnMbZtwm3TRIUTDGjB+IZGU7dPXgF8cK4KR4yDRZ5HKIZWbqxCPCP\n\
   6TphI+Jz83OxpXU9R8rfPgUhnBgqwTdDpc5pGfmyiQKBgQD+I1TKDW5tF0fXWnza\n\
   Xwoe0ULUM8TRXWBJmxfb1OkzmNLiq/jor6zxibXOas5EzzH5zKd8/HVVBlDfgRh4\n\
   IwhfbXavIn7MMBOXg0TQjia4y9KIf2/HpdzsWaE2dpjM+wEvlOb2ea1C4/T1gSfy\n\
   miI4kWIOz/iiWcPmiADk7hMcaQKBgQDkwgupZgFS6psRYtG0yu5S2kBJyWsGo02w\n\
   kSwwZt6oEmagzF0d5JlyRss6uqbsaUzI1Ek17/m5ZEZLNoxi4abCw+kRHOoS9gWd\n\
   KumNbli1dn4m3EVc1V+b1nWAsuC8ak5QIhRFumgNyQN7W+BS6TfLn4ONmKGz6uog\n\
   njlfNdPMGQKBgFa5/ex6Cu4lnLmsQqFO/6gmp5S9GfSM1hgoWksF7JNUGtuJ7oaR\n\
   tQY0hZusrTmkL5zcr2eiy/O5FQ5BAvW0lt3iADeiIP1ThswU2v4FFMfJns5AFwhd\n\
   3Pe3WqG4dUq2eeAgA3Wnbm4+VtEVQ2myGe2OB5WgeWwGEClyzkNRz6nJAoGAPN4c\n\
   +D/6DjP6es/OeMqeS1FjVb7QSX3eSCL4nRBiIlpzEEoQZMnUwoFvxfqwO6txEObb\n\
   bAykZ930jkK/a/gaxSwXscP9zHnF2KH4bvdzhyU2P+TQV/k2bWLM9SejgL7Qg6Xt\n\
   uvf0g+Z+lK5HrAf+HqIdAOoh7JuPHIq9PUY3StECgYEAoYP7hkj8TUygnkJcHxwM\n\
   MwdqBsTdyr8O2ZjMTa/UMWlBi7kjg8KblzsRB4g/p1m2/wgyC0Yhv3VBf2le8/Rr\n\
   OfNArBggDydmCgQ0I9+IxM+IQNP17/SU5s71daxeltJOxE+PSy/WsH5TMEnQ+CMr\n\
   irbM4XSw2jtvX7qeUzcFY/E=\n\
   -----END PRIVATE KEY-----\n"

let testkey_jwk = Jose.Jwk.of_priv_pem testkey_pem |> Result.get_ok

let expected_protected =
  "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZuaWN4emg2V0VUUWxydmRj"
  ^ "aGt6LVUzZTNET1FaNGhlSktVNjNyZnFNcVEiLCJqd2siOnsiZSI6"
  ^ "IkFRQUIiLCJuIjoiNHhnWjNlUlBrd29Sdnk3cWVSVWJtTURlMFYt"
  ^ "eEg5ZVdMZHUwaWhlZUxscm1EMm1xV1hmUDlJZVNLQXBibjM0ZzhU"
  ^ "dUFTOWc1emhxOEVMUTNrbWpyLUtWODZHQU1nSTZWQWNHbHEzUXJ6"
  ^ "cFRDZl8zMEFiNy16YXdyZlJhRk9OYTFId0V6UFkxS0huR1ZreEpj"
  ^ "ODVnTmt3WUk5U1kyUkhYdHZsbjN6czV3SVROcmRvc3FFWGVhSWtW"
  ^ "WUJFaGJoTnU1NHBwM2t4bzZUdVdMaTllNnBYZVdldEV3bWxCd3RX"
  ^ "WmxQb2liMmozVHhMQmtzS1pmb3lGeWVrMzgwbUhnSkF1bVFfSTJm"
  ^ "amo5OF85N21rM2loT1k0QWdWZENEajF6X0dDb1prRzVScTduYkNH"
  ^ "eW9zeUtXeURYMDBacy1uTnFWaG9MZUl2WEM0bm5XZEpNWjZyb2d4"
  ^ "eVFRIiwia3R5IjoiUlNBIiwia2lkIjoiNm5pY3h6aDZXRVRRbHJ2"
  ^ "ZGNoa3otVTNlM0RPUVo0aGVKS1U2M3JmcU1xUSIsIng1dCI6Ijk4"
  ^ "WEZNbUZxRWtrb0RudTdHSjhjRFdGaTJJWSJ9LCJub25jZSI6Im5v" ^ "bmNlIn0"

let expected_payload = "eyJNc2ciOiJIZWxsbyBKV1MifQ"
let expected_decoded_payload = {|{"Msg":"Hello JWS"}|}

let expected_signature =
  "qv79C1SFoz_7EWt7WVIhg5kVBPbCK__Xa1kFtodtS7hD78KvRQrU"
  ^ "Cx4Usa5T6PrFKmutXumyArjW3RxwRa1ATKo7g8k-F0TeUELXsZic"
  ^ "fLs_5jHu8vj3g47_mlhjMg9oJ6YNDVdhg3Gm19ZXgm6W_WlnM8wC"
  ^ "2dUVVSVYLxP7Hk2b6urM_tXJ3HtWRHbmQtD8hxQaMCNzz99usPvA"
  ^ "I1SW5b-I1rK0dxIOZ205Kce4VtLgEVs9hz45b4t93-g0bP1clHCU"
  ^ "iNKf-vzOs_45H1EKkxEpGDO5fQkeNfoQxTsE03AnB9SZXiF-ApDW"
  ^ "QMz_4f3YJ9YhRVB1iXx9vgAMkqhTaQ"

let jws_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "JWS"
    [
      ( "JWS",
        [
          Alcotest.test_case "fail to parse {}" `Quick (fun () ->
              let jws_string = "{}" in
              let jws_result = Jose.Jws.of_string jws_string in
              check_result_string "failing to parse"
                (Result.map (fun (jws : Jose.Jws.t) -> jws.payload) jws_result)
                (Error (`Msg "no payload")));
          Alcotest.test_case "parses a flattened json representation correctly"
            `Quick (fun () ->
              let jws_string =
                Printf.sprintf
                  {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
                  expected_protected expected_payload expected_signature
              in
              let validated =
                Jose.Jws.of_string jws_string
                |> CCResult.flat_map (Jose.Jws.validate ~jwk:testkey_jwk)
              in
              check_result_string "Correct signature"
                (Result.map (fun (jws : Jose.Jws.t) -> jws.signature) validated)
                (Ok expected_signature);
              check_result_string "Correct payload"
                (Result.map (fun (jws : Jose.Jws.t) -> jws.payload) validated)
                (Ok expected_decoded_payload));
          Alcotest.test_case "Produces the same output" `Quick (fun () ->
              let header =
                Jose.Header.make_header
                  ~extra:[ ("nonce", `String "nonce") ]
                  ~jwk_header:true testkey_jwk
              in
              let jws =
                Jose.Jws.sign ~header ~payload:expected_decoded_payload
                  testkey_jwk
              in
              let jws_string =
                Result.map (Jose.Jws.to_string ~serialization:`Flattened) jws
              in
              let expected_jws_string =
                Printf.sprintf
                  {|{"payload":"%s","protected":"%s","signature":"%s"}|}
                  expected_payload expected_protected expected_signature
              in
              check_result_string "matches original jws"
                (Ok expected_jws_string) jws_string);
          Alcotest.test_case "Roundtrip with ES384" `Quick (fun () ->
              let priv_string =
                {|{
                  "alg":"ES384",
                  "crv":"P-384",
                  "x":"rxz9m2FeRvvTE7_lSSSLve2c_ZkXxAasRId4jLqzIlsud19DtF52LOn91mQTRP9Y",
                  "y":"3_G1QTpidcws41ep1nLoc--6fHQjPXgu-oVuZhXB7VSihC3nLrF4irfhlB8cmTsa",
                  "d":"9eZFD1YrsUj5yQKj5u3Rju-Wx4JPL1TGXDWS1zE8AvYAmz_1Hp62R_oTtk1H7ARH",
                  "kty":"EC",
                  "kid":"W1X4opFJerkT7BFhQaf1-A5fRZTBJBmuJwerrUEcU4c"
                }|}
              in
              let jwk =
                Jose.Jwk.of_priv_json_string priv_string |> Result.get_ok
              in
              let jws = Jose.Jws.sign ~payload:"hello" jwk in
              let jws_string = Result.map Jose.Jws.to_string jws in
              let validated =
                jws_string
                |> CCResult.flat_map Jose.Jws.of_string
                |> CCResult.flat_map (Jose.Jws.validate ~jwk)
              in
              let pub_jwk = Jose.Jwk.pub_of_priv jwk in
              let _validated =
                CCResult.flat_map (Jose.Jws.validate ~jwk:pub_jwk) jws
              in

              check_result_string "Correct payload" (Ok "hello")
                (Result.map (fun (jws : Jose.Jws.t) -> jws.payload) validated));
        ] );
    ]

let jws_suite = jws_suite
