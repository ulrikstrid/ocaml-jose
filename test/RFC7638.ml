open Helpers
module Jwk = Jose.Jwk

let get_thumbprint jwk = Jwk.get_thumbprint `SHA256 jwk
let get_ok_thumbprint jwk = get_thumbprint jwk |> CCResult.get_exn

let public_rsa_thumbprint () =
  let hashable_reference =
    Fixtures.public_jwk_string_rfc_7638_hashable
    |> Digestif.SHA256.digest_string |> Digestif.SHA256.to_raw_string
    |> url_encode_string
  in
  let hashed_reference = Fixtures.public_jwk_string_rfc_7638_hashed in
  let thumbprint =
    Fixtures.public_jwk_string_rfc_7638 |> Jwk.of_pub_json_string
    |> CCResult.get_exn |> get_ok_thumbprint
  in
  check_string "Hashes must match" hashable_reference
    (url_encode_string thumbprint);
  check_string "Hashes must match" hashed_reference
    (url_encode_string thumbprint)

let private_rsa_thumbprint () =
  let private_thumbprint =
    Fixtures.private_jwk_string |> Jwk.of_priv_json_string |> CCResult.get_exn
    |> get_ok_thumbprint |> url_encode_string
  in
  let public_thumbprint =
    Fixtures.public_jwk_string |> Jwk.of_pub_json_string |> CCResult.get_exn
    |> get_ok_thumbprint |> url_encode_string
  in
  check_string "Hashes must match" public_thumbprint private_thumbprint

let symmetric_thumbprint () =
  let jwk =
    Fixtures.oct_jwk_string |> Jwk.of_pub_json_string |> CCResult.get_exn
  in
  check_result_string "Errors must match" (Error `Unsafe)
    (Result.map url_encode_string @@ get_thumbprint jwk)

let ec_p256_priv_json =
  {|{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}|}

let ec_p256_pub_json =
  {|{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}|}

let ec_p256_canonical_json =
  {|{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}|}

let public_ec_thumbprint () =
  let expected_thumbprint =
    Digestif.SHA256.digest_string ec_p256_canonical_json
    |> Digestif.SHA256.to_raw_string |> url_encode_string
  in
  let actual_thumbprint =
    ec_p256_pub_json |> Jwk.of_pub_json_string |> CCResult.get_exn
    |> get_ok_thumbprint |> url_encode_string
  in
  check_string "EC public thumbprint matches canonical SHA-256 (RFC 7638 3.2)"
    expected_thumbprint actual_thumbprint

let private_ec_thumbprint () =
  let private_thumbprint =
    ec_p256_priv_json |> Jwk.of_priv_json_string |> CCResult.get_exn
    |> get_ok_thumbprint |> url_encode_string
  in
  let public_thumbprint =
    ec_p256_pub_json |> Jwk.of_pub_json_string |> CCResult.get_exn
    |> get_ok_thumbprint |> url_encode_string
  in
  check_string
    "Thumbprint from private EC key and its public key are the same (RFC 7638 \
     3.2.1)"
    public_thumbprint private_thumbprint

let tests =
  List.map make_test_case
    [
      ( "Correct fields are used from public RSA key to generate thumbprint",
        public_rsa_thumbprint );
      ( "Thumbprint from a private RSA key and its public key are the same",
        private_rsa_thumbprint );
      ("Thumbprint for symmetric keys is never calculated", symmetric_thumbprint);
      ( "Correct fields (crv, kty, x, y) are used from EC key to generate \
         thumbprint (RFC 7638 3.2)",
        public_ec_thumbprint );
      ( "Thumbprint from a private EC key and its public key are the same (RFC \
         7638 3.2.1)",
        private_ec_thumbprint );
    ]

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7638"
    [ ("RFC 7638", tests) ]
