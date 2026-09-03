(* Tests for Jose.Private.Utils *)
module Utils = Jose.Private.Utils
module Pkcs7 = Utils.Pkcs7
module U_String = Utils.U_String
module U_Base64 = Utils.U_Base64

let pkcs7_tests =
  ( "Pkcs7",
    [
      Alcotest.test_case
        "unpad empty string returns Error without raising exception" `Quick
        (fun () ->
          let raised, res =
            try (false, Pkcs7.unpad "")
            with e -> (true, Error (`Msg (Printexc.to_string e)))
          in
          Alcotest.(check bool) "does not raise exception on empty string" false
            raised;
          Alcotest.(check bool) "returns Error on empty string" true
            (CCResult.is_error res));
      Alcotest.test_case
        "unpad with pad_len > string length returns Error without raising \
         exception"
        `Quick (fun () ->
          (* "\x10" has length 1, but pad length is 16 *)
          let raised, res =
            try (false, Pkcs7.unpad "\x10")
            with e -> (true, Error (`Msg (Printexc.to_string e)))
          in
          Alcotest.(check bool) "does not raise exception on pad_len > len" false
            raised;
          Alcotest.(check bool) "returns Error on pad_len > len" true
            (CCResult.is_error res));
      Alcotest.test_case "unpad with pad_len = 0 returns Error" `Quick
        (fun () ->
          let res = Pkcs7.unpad "hello\x00" in
          Alcotest.(check bool) "pad_len 0 must be rejected as invalid padding"
            true (CCResult.is_error res));
      Alcotest.test_case "unpad with inconsistent padding bytes returns Error"
        `Quick (fun () ->
          (* Last byte says 4 bytes of padding, but preceding bytes are \x05 *)
          let res = Pkcs7.unpad "data\x05\x05\x05\x04" in
          Alcotest.(check bool)
            "inconsistent padding bytes must return Error" true
            (CCResult.is_error res));
      Alcotest.test_case
        "pad and unpad roundtrip across varying lengths with block_size 16"
        `Quick (fun () ->
          let test_lengths = [ 0; 1; 7; 15; 16; 17; 31; 32; 64; 100 ] in
          List.iter
            (fun len ->
              let input = String.make len 'x' in
              let padded = Pkcs7.pad input 16 in
              (* Padded length must always be a multiple of block_size and strictly > input length *)
              Alcotest.(check int)
                "padded length is multiple of block size" 0
                (String.length padded mod 16);
              Alcotest.(check bool)
                "padded length is strictly greater than input length" true
                (String.length padded > String.length input);
              let unpadded = Pkcs7.unpad padded in
              Alcotest.(check (result string (testable Fmt.nop ( = ))))
                "unpadded matches original input" (Ok input) unpadded)
            test_lengths);
    ] )

let u_string_tests =
  ( "U_String",
    [
      Alcotest.test_case "rev reverses strings correctly" `Quick (fun () ->
          Alcotest.(check string) "rev empty" "" (U_String.rev "");
          Alcotest.(check string) "rev single" "a" (U_String.rev "a");
          Alcotest.(check string) "rev text" "cba" (U_String.rev "abc"));
      Alcotest.test_case "split divides strings at correct index" `Quick
        (fun () ->
          let left, right = U_String.split "helloworld" 5 in
          Alcotest.(check string) "left is hello" "hello" left;
          Alcotest.(check string) "right is world" "world" right);
      Alcotest.test_case "pad adds leading characters" `Quick (fun () ->
          let padded = U_String.pad ~c:'0' ~len:5 "123" in
          Alcotest.(check string) "padded with leading zeros" "00123" padded);
    ] )

let u_base64_tests =
  ( "U_Base64",
    [
      Alcotest.test_case "url_encode_string and url_decode roundtrip" `Quick
        (fun () ->
          let msg = "Hello from OCaml JOSE! ?#$%" in
          let encoded = U_Base64.url_encode_string msg in
          let decoded = U_Base64.url_decode encoded |> CCResult.get_exn in
          Alcotest.(check string) "decoded matches original" msg decoded);
    ] )

let utils_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "Utils"
    [ pkcs7_tests; u_string_tests; u_base64_tests ]
