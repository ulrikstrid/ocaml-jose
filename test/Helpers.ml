let result_t :
    [> `Msg of string
    | `Expired
    | `Not_rsa
    | `Json_parse_failed of string
    | `Unsupported_kty ]
    Alcotest.testable =
  let pp ppf = function
    | `Msg e -> Fmt.string ppf e
    | `Expired -> Fmt.string ppf "expired"
    | `Not_rsa -> Fmt.string ppf "Expected RSA"
    | `Json_parse_failed s -> Fmt.string ppf ("Badly formed jwk json " ^ s)
    | `Unsupported_kty -> Fmt.string ppf "Unsupported kty"
  in
  Alcotest.testable pp ( = )

let check_string = Alcotest.(check string)

let check_result_string = Alcotest.(check (result string result_t))

let check_result_bool = Alcotest.(check (result bool result_t))

let check_option_string = Alcotest.(check (option string))

let check_int = Alcotest.(check int)

let trim_json_string str =
  str |> CCString.replace ~sub:" " ~by:"" |> CCString.replace ~sub:"\n" ~by:""
