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
          Alcotest.test_case "Fails validation when RSA JWK has incompatible alg" `Quick (fun () ->
              let jws = Jose.Jws.sign ~payload:"hello" testkey_jwk |> Result.get_ok in
              let jws_string = Jose.Jws.to_string jws in
              let incompatible_jwk =
                match testkey_jwk with
                | Jose.Jwk.Rsa_priv jwk -> Jose.Jwk.Rsa_priv { jwk with alg = Some `RSA_OAEP }
                | _ -> assert false
              in
              let validation =
                Jose.Jws.of_string jws_string
                |> CCResult.flat_map (Jose.Jws.validate ~jwk:incompatible_jwk)
              in
              check_result_bool "Validation failed due to incompatible alg"
                (Ok true)
                (Ok (CCResult.is_error validation)));
          Alcotest.test_case "of_compact_string error cases" `Quick (fun () ->
              let res_2segs = Jose.Jws.of_string "header.payload" in
              Alcotest.(check bool) "fails with 2 segments" true
                (res_2segs = Error (`Msg "token didn't include header, payload or signature"));
              let res_4segs = Jose.Jws.of_string "a.b.c.d" in
              Alcotest.(check bool) "fails with 4 segments" true
                (res_4segs = Error (`Msg "token didn't include header, payload or signature"));
              let header_str = Jose.Header.to_string (Jose.Header.make_header testkey_jwk) in
              let res_bad_payload = Jose.Jws.of_string (header_str ^ ".???invalid-b64???.sig") in
              Alcotest.(check bool) "fails on bad base64 payload" true
                (CCResult.is_error res_bad_payload));
          Alcotest.test_case "of_json_string error cases" `Quick (fun () ->
              let res_no_sig =
                Jose.Jws.of_string {|{"payload":"eyJNc2ciOiJIZWxsbyJ9","protected":"eyJhbGciOiJSUzI1NiJ9"}|}
              in
              Alcotest.(check bool) "fails with Not_supported when signature missing" true
                (res_no_sig = Error `Not_supported);
              let res_bad_json = Jose.Jws.of_string "{not valid json" in
              Alcotest.(check bool) "fails with Not_json on malformed json" true
                (res_bad_json = Error `Not_json));
          Alcotest.test_case "to_string serializations" `Quick (fun () ->
              let jws = Jose.Jws.sign ~payload:"test payload" testkey_jwk |> CCResult.get_exn in
              let compact = Jose.Jws.to_string ~serialization:`Compact jws in
              let general = Jose.Jws.to_string ~serialization:`General jws in
              let flattened = Jose.Jws.to_string ~serialization:`Flattened jws in
              Alcotest.(check bool) "compact starts with ey" true
                (CCString.prefix ~pre:"ey" compact);
              Alcotest.(check bool) "general returns Not_supported on of_string" true
                (Jose.Jws.of_string general = Error `Not_supported);
              Alcotest.(check bool) "flattened parses as JSON" true
                (CCResult.is_ok (Jose.Jws.of_string flattened)));
          Alcotest.test_case "Signing and verifying with ES256, ES512, Ed25519, and Oct" `Quick
            (fun () ->
              (* ES256 *)
              let es256_jwk_priv =
                Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn
              in
              let es256_jwk_pub = Jose.Jwk.pub_of_priv es256_jwk_priv in
              let jws_es256 = Jose.Jws.sign ~payload:"es256 payload" es256_jwk_priv |> CCResult.get_exn in
              Alcotest.(check bool) "ES256 validates with priv" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:es256_jwk_priv jws_es256));
              Alcotest.(check bool) "ES256 validates with pub" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:es256_jwk_pub jws_es256));

              (* ES512 *)
              let es512_jwk_priv =
                Jose.Jwk.of_priv_pem Fixtures.es512_test_priv |> CCResult.get_exn
              in
              let es512_jwk_pub = Jose.Jwk.pub_of_priv es512_jwk_priv in
              let jws_es512 = Jose.Jws.sign ~payload:"es512 payload" es512_jwk_priv |> CCResult.get_exn in
              Alcotest.(check bool) "ES512 validates with priv" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:es512_jwk_priv jws_es512));
              Alcotest.(check bool) "ES512 validates with pub" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:es512_jwk_pub jws_es512));

              (* Ed25519 *)
              let ed_priv, _ = Mirage_crypto_ec.Ed25519.generate () in
              let ed_jwk_priv =
                Jose.Jwk.Ed25519_priv
                  { alg = None; kty = `OKP; use = None; kid = None; key = ed_priv }
              in
              let ed_jwk_pub = Jose.Jwk.pub_of_priv ed_jwk_priv in
              let jws_ed = Jose.Jws.sign ~payload:"ed payload" ed_jwk_priv |> CCResult.get_exn in
              Alcotest.(check bool) "Ed25519 validates with priv" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:ed_jwk_priv jws_ed));
              Alcotest.(check bool) "Ed25519 validates with pub" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:ed_jwk_pub jws_ed));

              (* Oct *)
              let oct_jwk = Jose.Jwk.make_oct "shared-secret" in
              let jws_oct = Jose.Jws.sign ~payload:"oct payload" oct_jwk |> CCResult.get_exn in
              Alcotest.(check bool) "Oct validates" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:oct_jwk jws_oct)));
          Alcotest.test_case "Invalid signature detection across all key types" `Quick
            (fun () ->
              let bad_sig = url_encode_string (String.make 64 '\x00') in
              let bad_sig_96 = url_encode_string (String.make 96 '\x00') in
              let bad_sig_132 = url_encode_string (String.make 132 '\x00') in
              let bad_sig_32 = url_encode_string (String.make 32 '\x00') in
              let bad_sig_64 = url_encode_string (String.make 64 '\x00') in

              (* RSA Pub *)
              let rsa_pub = Jose.Jwk.pub_of_priv testkey_jwk in
              let jws_rsa = Jose.Jws.sign ~payload:"hello" testkey_jwk |> CCResult.get_exn in
              let jws_rsa_tampered = { jws_rsa with payload = "tampered" } in
              Alcotest.(check bool) "RSA pub detects tampered payload" true
                (Jose.Jws.validate ~jwk:rsa_pub jws_rsa_tampered = Error (`Msg "payload does not match"));
              let jws_rsa_short_sig = { jws_rsa with signature = url_encode_string "short" } in
              Alcotest.(check bool) "RSA priv catches Invalid_argument on short signature" true
                (CCResult.is_error (Jose.Jws.validate ~jwk:testkey_jwk jws_rsa_short_sig));
              Alcotest.(check bool) "RSA pub catches Invalid_argument on short signature" true
                (CCResult.is_error (Jose.Jws.validate ~jwk:rsa_pub jws_rsa_short_sig));

              (* ES256 *)
              let es256_priv =
                Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn
              in
              let es256_pub = Jose.Jwk.pub_of_priv es256_priv in
              let jws_es256 = Jose.Jws.sign ~payload:"hello" es256_priv |> CCResult.get_exn in
              let jws_es256_bad = { jws_es256 with signature = bad_sig } in
              Alcotest.(check bool) "ES256 pub invalid sig" true
                (Jose.Jws.validate ~jwk:es256_pub jws_es256_bad = Error `Invalid_signature);
              Alcotest.(check bool) "ES256 priv invalid sig" true
                (Jose.Jws.validate ~jwk:es256_priv jws_es256_bad = Error `Invalid_signature);

              (* ES384 *)
              let es384_priv, _ = Mirage_crypto_ec.P384.Dsa.generate () in
              let es384_jwk_priv =
                Jose.Jwk.of_priv_x509 (`P384 es384_priv) |> CCResult.get_exn
              in
              let es384_jwk_pub = Jose.Jwk.pub_of_priv es384_jwk_priv in
              let jws_es384 = Jose.Jws.sign ~payload:"hello" es384_jwk_priv |> CCResult.get_exn in
              let jws_es384_bad = { jws_es384 with signature = bad_sig_96 } in
              Alcotest.(check bool) "ES384 pub invalid sig" true
                (Jose.Jws.validate ~jwk:es384_jwk_pub jws_es384_bad = Error `Invalid_signature);
              Alcotest.(check bool) "ES384 priv invalid sig" true
                (Jose.Jws.validate ~jwk:es384_jwk_priv jws_es384_bad = Error `Invalid_signature);

              (* ES512 *)
              let es512_priv =
                Jose.Jwk.of_priv_pem Fixtures.es512_test_priv |> CCResult.get_exn
              in
              let es512_pub = Jose.Jwk.pub_of_priv es512_priv in
              let jws_es512 = Jose.Jws.sign ~payload:"hello" es512_priv |> CCResult.get_exn in
              let jws_es512_bad = { jws_es512 with signature = bad_sig_132 } in
              Alcotest.(check bool) "ES512 pub invalid sig" true
                (Jose.Jws.validate ~jwk:es512_pub jws_es512_bad = Error `Invalid_signature);
              Alcotest.(check bool) "ES512 priv invalid sig" true
                (Jose.Jws.validate ~jwk:es512_priv jws_es512_bad = Error `Invalid_signature);

              (* Ed25519 *)
              let ed_priv, _ = Mirage_crypto_ec.Ed25519.generate () in
              let ed_jwk_priv =
                Jose.Jwk.Ed25519_priv
                  { alg = None; kty = `OKP; use = None; kid = None; key = ed_priv }
              in
              let ed_jwk_pub = Jose.Jwk.pub_of_priv ed_jwk_priv in
              let jws_ed = Jose.Jws.sign ~payload:"hello" ed_jwk_priv |> CCResult.get_exn in
              let jws_ed_bad = { jws_ed with signature = bad_sig_64 } in
              Alcotest.(check bool) "Ed25519 pub invalid sig" true
                (Jose.Jws.validate ~jwk:ed_jwk_pub jws_ed_bad = Error `Invalid_signature);
              Alcotest.(check bool) "Ed25519 priv invalid sig" true
                (Jose.Jws.validate ~jwk:ed_jwk_priv jws_ed_bad = Error `Invalid_signature);

              (* Oct *)
              let oct_jwk = Jose.Jwk.make_oct "secret" in
              let jws_oct = Jose.Jws.sign ~payload:"hello" oct_jwk |> CCResult.get_exn in
              let jws_oct_bad = { jws_oct with signature = bad_sig_32 } in
              Alcotest.(check bool) "Oct invalid sig" true
                (Jose.Jws.validate ~jwk:oct_jwk jws_oct_bad = Error `Invalid_signature));
          Alcotest.test_case "rsa_validate_hash for RS384, RS512 and None alg" `Quick
            (fun () ->
              let rsa_priv =
                match testkey_jwk with
                | Jose.Jwk.Rsa_priv jwk -> jwk
                | _ -> assert false
              in
              let header_rs256 = Jose.Header.make_header testkey_jwk in
              let header_str = Jose.Header.to_string header_rs256 in
              let payload_str = url_encode_string "hello rsa" in
              let input_str = Printf.sprintf "%s.%s" header_str payload_str in

              (* Sign with SHA384 *)
              let sig384 =
                Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:`SHA384 ~key:rsa_priv.key (`Message input_str)
                |> url_encode_string
              in
              let jws384 : Jose.Jws.t =
                {
                  header = header_rs256;
                  raw_header = header_str;
                  payload = "hello rsa";
                  signature = sig384;
                }
              in
              let jwk_rs384 = Jose.Jwk.Rsa_priv { rsa_priv with alg = Some (`Unsupported "RS384") } in
              let jwk_none = Jose.Jwk.Rsa_priv { rsa_priv with alg = None } in
              Alcotest.(check bool) "validates with RS384 alg" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:jwk_rs384 jws384));
              Alcotest.(check bool) "validates with None alg on SHA384" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:jwk_none jws384));

              (* Sign with SHA512 *)
              let sig512 =
                Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:`SHA512 ~key:rsa_priv.key (`Message input_str)
                |> url_encode_string
              in
              let jws512 : Jose.Jws.t =
                {
                  header = header_rs256;
                  raw_header = header_str;
                  payload = "hello rsa";
                  signature = sig512;
                }
              in
              let jwk_rs512 = Jose.Jwk.Rsa_priv { rsa_priv with alg = Some (`Unsupported "RS512") } in
              Alcotest.(check bool) "validates with RS512 alg" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:jwk_rs512 jws512));
              Alcotest.(check bool) "validates with None alg on SHA512" true
                (CCResult.is_ok (Jose.Jws.validate ~jwk:jwk_none jws512)));
          Alcotest.test_case "sign with invalid Oct key errors" `Quick (fun () ->
              let bad_oct_jwk =
                Jose.Jwk.Oct
                  {
                    alg = Some `HS256;
                    kty = `oct;
                    use = None;
                    kid = None;
                    key = "???invalid-b64???";
                  }
              in
              let res = Jose.Jws.sign ~payload:"hello" bad_oct_jwk in
              Alcotest.(check bool) "sign fails on invalid oct key" true
                (CCResult.is_error res));
        ] );
    ]

let jws_suite = jws_suite
