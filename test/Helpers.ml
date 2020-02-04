let result_t : [ `Msg of string ] Alcotest.testable =
  let pp ppf = function `Msg e -> Fmt.string ppf e in
  Alcotest.testable pp ( = )

let check_string = Alcotest.(check string)

let check_result_string = Alcotest.(check (result string result_t))

let check_result_bool = Alcotest.(check (result bool result_t))

let check_option_string = Alcotest.(check (option string))

let check_int = Alcotest.(check int)
