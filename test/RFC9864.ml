(* Tests for RFC 9864 (Fully-Specified Algorithms for JOSE) *)
let () = Mirage_crypto_rng_unix.use_default ()

let ed25519_priv_json =
  {|{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}|}

let ed25519_pub_json =
  {|{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}|}

let ed25519_priv =
  Jose.Jwk.of_priv_json_string ed25519_priv_json |> CCResult.get_exn

let ed25519_pub =
  Jose.Jwk.of_pub_json_string ed25519_pub_json |> CCResult.get_exn

let rfc9864_tests =
  ( "RFC9864",
    [
      Alcotest.test_case
        "RFC 9864: Inbound JWS with alg Ed25519 validates successfully" `Quick
        (fun () ->
          let header_json = `Assoc [ ("alg", `String "Ed25519") ] in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let payload = "Example of Ed25519 signing per RFC 9864" in
          let jws =
            Jose.Jws.sign ~header ~payload ed25519_priv |> CCResult.get_exn
          in
          let validated = Jose.Jws.validate ~jwk:ed25519_pub jws in
          Alcotest.(check bool) "Ed25519 JWS validates with public key" true
            (CCResult.is_ok validated));
      Alcotest.test_case
        "RFC 9864: Header.make_header emits Ed25519 as default alg for \
         Ed25519_priv"
        `Quick (fun () ->
          let header = Jose.Header.make_header ed25519_priv in
          let alg_str = Jose.Jwa.alg_to_string header.alg in
          Alcotest.(check string)
            "Default algorithm for Ed25519 key must be Ed25519 (RFC 9864)"
            "Ed25519" alg_str);
      Alcotest.test_case
        "RFC 9864: Backward compatibility - deprecated EdDSA algorithm \
         continues to validate"
        `Quick (fun () ->
          let header_json = `Assoc [ ("alg", `String "EdDSA") ] in
          let header = Jose.Header.of_json header_json |> CCResult.get_exn in
          let payload = "Legacy EdDSA token" in
          let jws =
            Jose.Jws.sign ~header ~payload ed25519_priv |> CCResult.get_exn
          in
          let validated = Jose.Jws.validate ~jwk:ed25519_pub jws in
          Alcotest.(check bool) "Legacy EdDSA JWS validates with public key" true
            (CCResult.is_ok validated));
    ] )

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC9864" [ rfc9864_tests ]
