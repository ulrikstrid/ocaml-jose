let result_t :
    [> `Msg of string
    | `Expired
    | `Not_rsa
    | `Json_parse_failed of string
    | `Unsupported_kty
    | `Invalid_signature
    | `Missing_use_and_alg
    | `Invalid_JWE
    | `Invalid_JWK
    | `Decrypt_cek_failed ]
    Alcotest.testable =
  let pp ppf = function
    | `Msg e -> Fmt.string ppf e
    | `Expired -> Fmt.string ppf "expired"
    | `Not_rsa -> Fmt.string ppf "Expected RSA"
    | `Json_parse_failed s -> Fmt.string ppf ("Badly formed json " ^ s)
    | `Unsupported_kty -> Fmt.string ppf "Unsupported kty"
    | `Invalid_signature -> Fmt.string ppf "Invalid signature"
    | `Missing_use_and_alg -> Fmt.string ppf "Missing use and alg"
    | `Invalid_JWE -> Fmt.string ppf "Invalid JWE"
    | `Invalid_JWK -> Fmt.string ppf "Invalid JWK"
    | `Decrypt_cek_failed -> Fmt.string ppf "Failed to decrypt cek"
  in
  Alcotest.testable pp ( = )

let check_string = Alcotest.(check string)

let check_result_string = Alcotest.(check (result string result_t))

let check_result_bool = Alcotest.(check (result bool result_t))

let check_option_string = Alcotest.(check (option string))

let check_int = Alcotest.(check int)

let trim_json_string str =
  str |> CCString.replace ~sub:" " ~by:"" |> CCString.replace ~sub:"\n" ~by:""
