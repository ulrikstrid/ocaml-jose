open Helpers
module Jwk = Jose.Jwk

let get_thumbprint jwk = Jwk.get_thumbprint `SHA256 jwk
let get_ok_thumbprint jwk = get_thumbprint jwk |> CCResult.get_exn

let ed25519_private_json =
  {|{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}|}

let ed25519_public_json =
  {|{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}|}

let ed25519_jws =
  "eyJhbGciOiJFZERTQSJ9." ^ "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
  ^ "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt"
  ^ "9g7sVvpAr_MuM0KAg"

let ed25519_jws_header_string = {|{"alg":"EdDSA"}|}

let ed25519_jws_header =
  Jose.Header.
    {
      alg = `EdDSA;
      jwk = None;
      kid = None;
      x5t = None;
      x5t256 = None;
      typ = None;
      cty = None;
      enc = None;
      extra = [];
    }

let ed25519_jws_payload = "Example of Ed25519 signing"

let a_1 () =
  let jwk = Jwk.of_priv_json_string ed25519_private_json in
  check_result_string "generates same" (Ok ed25519_private_json)
    (Result.map Jwk.to_priv_json_string jwk)

let a_2 () =
  let jwk = Jwk.of_pub_json_string ed25519_public_json in
  check_result_string "generates same" (Ok ed25519_public_json)
    (Result.map Jwk.to_pub_json_string jwk);
  let jwk = Jwk.of_priv_json_string ed25519_private_json in
  check_result_string "generates correct pub from priv" (Ok ed25519_public_json)
    (Result.map Jwk.to_pub_json_string jwk)

let a_3 () =
  let jwk = Jwk.of_pub_json_string ed25519_public_json in
  check_result_string "Correct thumbprint"
    (Ok "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
    (CCResult.flat_map get_thumbprint jwk |> CCResult.map url_encode_cstruct);
  let priv_jwk = Jwk.of_priv_json_string ed25519_private_json in
  check_result_string "Correct thumbprint from private"
    (Ok "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
    (CCResult.flat_map get_thumbprint priv_jwk
    |> CCResult.map url_encode_cstruct)

let a_4 () =
  let jwk = Jwk.of_priv_json_string ed25519_private_json in
  let jws =
    CCResult.flat_map
      (Jose.Jws.sign ~header:ed25519_jws_header ~payload:ed25519_jws_payload)
      jwk
  in
  let jws_string = CCResult.map Jose.Jws.to_string jws in
  check_result_string "Generates same output as input" (Ok ed25519_jws)
    jws_string

let a_5 () =
  let jwk = Jwk.of_pub_json_string ed25519_public_json |> Result.get_ok in
  let jws = Jose.Jws.of_string ed25519_jws in
  let validated_jws = CCResult.flat_map (Jose.Jws.validate ~jwk) jws in
  check_result_string "Has same payload" (Ok ed25519_jws_payload)
    (Result.map (fun (jws : Jose.Jws.t) -> jws.payload) validated_jws);
  let private_jwk =
    Jwk.of_priv_json_string ed25519_private_json |> Result.get_ok
  in
  let validated_jws =
    CCResult.flat_map (Jose.Jws.validate ~jwk:private_jwk) jws
  in
  check_result_string "Has same payload" (Ok ed25519_jws_payload)
    (Result.map (fun (jws : Jose.Jws.t) -> jws.payload) validated_jws)

let tests =
  List.map make_test_case
    [
      ("A.1. Ed25519 Private Key", a_1);
      ("A.2. Ed25519 Public Key", a_2);
      ("A.3. JWK Thumbprint Canonicalization", a_3);
      ("A.4. Ed25519 Signing", a_4);
      ("A.5. Ed25519 Validation", a_5);
    ]

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC8037"
    [ ("RFC 8037", tests) ]
