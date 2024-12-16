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

let tests =
  List.map make_test_case
    [
      ( "Correct fields are used from public RSA key to generate thumbprint",
        public_rsa_thumbprint );
      ( "Thumbprint from a private RSA key and its public key are the same",
        private_rsa_thumbprint );
      ("Thumbprint for symmetric keys is never calculated", symmetric_thumbprint);
    ]

let suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7638"
    [ ("RFC 7638", tests) ]
