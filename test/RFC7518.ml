(* Tests for RFC 7518 (JSON Web Algorithms) *)
let () = Mirage_crypto_rng_unix.use_default ()
let rsa_priv = Jose.Jwk.of_priv_pem Fixtures.rsa_test_priv |> CCResult.get_exn
let rsa_pub = Jose.Jwk.pub_of_priv rsa_priv
let oct_jwk = Jose.Jwk.make_oct "my-secret-key-384-512-testing"

let rsa_priv_jwk =
  Fixtures.rsa_priv_enc_json |> Jose.Jwk.of_priv_json_string |> CCResult.get_exn

let jwa_tests =
  ( "RFC7518",
    [
      Alcotest.test_case "3.1: ES256 (Recommended+) signing and validation"
        `Quick (fun () ->
          let es256_priv =
            Jose.Jwk.of_priv_pem Fixtures.es256_test_priv |> CCResult.get_exn
          in
          let es256_pub = Jose.Jwk.pub_of_priv es256_priv in
          let header = Jose.Header.make_header ~alg:`ES256 es256_priv in
          let payload = "hello ES256 RFC 7518" in
          let jws =
            Jose.Jws.sign ~header ~payload es256_priv |> CCResult.get_exn
          in
          let validated = Jose.Jws.validate ~jwk:es256_pub jws in
          Alcotest.(check bool) "ES256 signature validates with public key" true
            (CCResult.is_ok validated);
          let tampered_jws = { jws with payload = "tampered payload" } in
          let res_tampered = Jose.Jws.validate ~jwk:es256_pub tampered_jws in
          Alcotest.(check bool) "ES256 validation fails on tampered payload" true
            (CCResult.is_error res_tampered));
      Alcotest.test_case "4.1: RSA-OAEP-256 key management support in JWE"
        `Quick (fun () ->
          let header_json =
            `Assoc
              [ ("alg", `String "RSA-OAEP-256"); ("enc", `String "A256GCM") ]
          in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let jwe_res = Jose.Jwe.make ~header "secret payload" in
          Alcotest.(check bool)
            "Jwe.make succeeds with RSA-OAEP-256" true (CCResult.is_ok jwe_res));
      Alcotest.test_case "5.3: A256GCM IV length is 96 bits (12 bytes)" `Quick
        (fun () ->
          let header =
            Jose.Header.make_header ~alg:`RSA_OAEP ~enc:`A256GCM rsa_priv_jwk
          in
          let jwe =
            Jose.Jwe.make ~header "secret message" |> CCResult.get_exn
          in
          Alcotest.(check int)
            "A256GCM IV length must be 12 bytes (96 bits)" 12
            (String.length jwe.iv));
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7518" [ jwa_tests ]
