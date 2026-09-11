type 'a error_t =
  [> `Msg of string
  | `Expired
  | `Json_parse_failed of string
  | `Unsupported_kty
  | `Unsupported_alg
  | `Unsupported_enc
  | `Missing_enc
  | `Invalid_alg
  | `Invalid_signature
  | `Invalid_JWE
  | `Invalid_JWK
  | `Decrypt_cek_failed
  | `Unsafe
  | `Not_json
  | `Not_supported ]
  as
  'a

let error_pp ppf (error : 'a error_t) =
  match error with
  | `Msg e -> Fmt.string ppf e
  | `Expired -> Fmt.string ppf "expired"
  | `Json_parse_failed s -> Fmt.string ppf ("Badly formed json " ^ s)
  | `Unsupported_kty -> Fmt.string ppf "Unsupported kty"
  | `Unsupported_alg -> Fmt.string ppf "Unsupported alg"
  | `Unsupported_enc -> Fmt.string ppf "Unsupported enc"
  | `Missing_enc -> Fmt.string ppf "Missing enc"
  | `Invalid_alg -> Fmt.string ppf "Invalid alg"
  | `Invalid_signature -> Fmt.string ppf "Invalid signature"
  | `Invalid_JWE -> Fmt.string ppf "Invalid JWE"
  | `Invalid_JWK -> Fmt.string ppf "Invalid JWK"
  | `Decrypt_cek_failed -> Fmt.string ppf "Failed to decrypt cek"
  | `Unsafe -> Fmt.string ppf "Unsafe"
  | `Not_json -> Fmt.string ppf "Not_json"
  | `Not_supported -> Fmt.string ppf "Not_supported"

let error_to_string e = Format.asprintf "%a" error_pp e
let result_t : _ error_t Alcotest.testable = Alcotest.testable error_pp ( = )
let check_string = Alcotest.(check string)
let check_result_string = Alcotest.(check (result string result_t))
let check_result_bool = Alcotest.(check (result bool result_t))

let check_option_string name expected actual =
  Alcotest.(check (option string)) name (Some expected) actual

let check_option_int name expected actual =
  Alcotest.(check (option int)) name (Some expected) actual

let check_int = Alcotest.(check int)

let trim_json_string str =
  str |> CCString.replace ~sub:" " ~by:"" |> CCString.replace ~sub:"\n" ~by:""

let make_test_case (name, test) = Alcotest.test_case name `Quick test

let url_encode_string ?(pad = false) payload =
  Base64.encode_string ~pad ~alphabet:Base64.uri_safe_alphabet payload

let url_decode_string ?(pad = false) payload =
  Base64.decode ~pad ~alphabet:Base64.uri_safe_alphabet payload
