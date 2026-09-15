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
          Alcotest.(check bool)
            "does not raise exception on empty string" false raised;
          Alcotest.(check bool)
            "returns Error on empty string" true (CCResult.is_error res));
      Alcotest.test_case
        "unpad with pad_len > string length returns Error without raising \
         exception"
        `Quick (fun () ->
          (* "\x10" has length 1, but pad length is 16 *)
          let raised, res =
            try (false, Pkcs7.unpad "\x10")
            with e -> (true, Error (`Msg (Printexc.to_string e)))
          in
          Alcotest.(check bool)
            "does not raise exception on pad_len > len" false raised;
          Alcotest.(check bool)
            "returns Error on pad_len > len" true (CCResult.is_error res));
      Alcotest.test_case "unpad with pad_len = 0 returns Error" `Quick
        (fun () ->
          let res = Pkcs7.unpad "hello\x00" in
          Alcotest.(check bool)
            "pad_len 0 must be rejected as invalid padding" true
            (CCResult.is_error res));
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

let of_hex s =
  let len = String.length s in
  let b = Bytes.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Bytes.set_uint8 b i byte
  done;
  Bytes.to_string b

let aes_kw_tests =
  ( "Aes_kw",
    [
      Alcotest.test_case
        "RFC 3394 4.1: Wrap and unwrap 128-bit key with 128-bit KEK" `Quick
        (fun () ->
          let kek = of_hex "000102030405060708090A0B0C0D0E0F" in
          let key_data = of_hex "00112233445566778899AABBCCDDEEFF" in
          let expected_ciphertext =
            of_hex "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
          in
          let wrapped = Utils.Aes_kw.wrap ~kek key_data |> CCResult.get_exn in
          Alcotest.(check string)
            "RFC 3394 4.1 ciphertext matches" expected_ciphertext wrapped;
          let unwrapped =
            Utils.Aes_kw.unwrap ~kek wrapped |> CCResult.get_exn
          in
          Alcotest.(check string)
            "RFC 3394 4.1 unwrap matches key data" key_data unwrapped);
      Alcotest.test_case
        "RFC 3394 4.6: Wrap and unwrap 256-bit key with 256-bit KEK" `Quick
        (fun () ->
          let kek =
            of_hex
              "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
          in
          let key_data =
            of_hex
              "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"
          in
          let expected_ciphertext =
            of_hex
              "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
          in
          let wrapped = Utils.Aes_kw.wrap ~kek key_data |> CCResult.get_exn in
          Alcotest.(check string)
            "RFC 3394 4.6 ciphertext matches" expected_ciphertext wrapped;
          let unwrapped =
            Utils.Aes_kw.unwrap ~kek wrapped |> CCResult.get_exn
          in
          Alcotest.(check string)
            "RFC 3394 4.6 unwrap matches key data" key_data unwrapped);
      Alcotest.test_case
        "RFC 7516 Appendix A.3: AES Key Wrap (A128KW) roundtrip" `Quick
        (fun () ->
          let kek =
            Utils.U_Base64.url_decode "GawgguFyGrWKav7AX4VKUg"
            |> CCResult.get_exn
          in
          let expected_wrapped =
            Utils.U_Base64.url_decode
              "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
            |> CCResult.get_exn
          in
          let unwrapped =
            Utils.Aes_kw.unwrap ~kek expected_wrapped |> CCResult.get_exn
          in
          Alcotest.(check int)
            "recovered CEK is 256 bits (32 bytes)" 32 (String.length unwrapped);
          let rewound = Utils.Aes_kw.wrap ~kek unwrapped |> CCResult.get_exn in
          Alcotest.(check string)
            "rewrapped matches expected A.3 JWE Encrypted Key" expected_wrapped
            rewound);
      Alcotest.test_case
        "Integrity check: unwrap fails when ciphertext is tampered" `Quick
        (fun () ->
          let kek = of_hex "000102030405060708090A0B0C0D0E0F" in
          let key_data = of_hex "00112233445566778899AABBCCDDEEFF" in
          let wrapped = Utils.Aes_kw.wrap ~kek key_data |> CCResult.get_exn in
          let corrupted = Bytes.of_string wrapped in
          let b0 = Bytes.get_uint8 corrupted 0 in
          Bytes.set_uint8 corrupted 0 (b0 lxor 0x01);
          let res = Utils.Aes_kw.unwrap ~kek (Bytes.to_string corrupted) in
          Alcotest.(check bool)
            "tampered ciphertext returns Error" true (CCResult.is_error res));
      Alcotest.test_case "Invalid input lengths are rejected" `Quick (fun () ->
          let kek = of_hex "000102030405060708090A0B0C0D0E0F" in
          Alcotest.(check bool)
            "wrap rejects non-multiple of 8" true
            (CCResult.is_error (Utils.Aes_kw.wrap ~kek "1234567"));
          Alcotest.(check bool)
            "wrap rejects plaintext < 16 bytes" true
            (CCResult.is_error (Utils.Aes_kw.wrap ~kek "12345678"));
          Alcotest.(check bool)
            "unwrap rejects ciphertext < 24 bytes" true
            (CCResult.is_error (Utils.Aes_kw.unwrap ~kek "1234567812345678")));
    ] )

let concat_kdf_tests =
  ( "Concat_kdf",
    [
      Alcotest.test_case
        "RFC 7518 Appendix C: Concat KDF with A128GCM (128-bit key)" `Quick
        (fun () ->
          let z =
            "\x9e\x56\xd9\x1d\x81\x71\x35\xd3\x72\x83\x42\x83\xbf\x84\x26\x9c\xfb\x31\x6e\xa3\xda\x80\x6a\x48\xf6\xda\xa7\x79\x8c\xfe\x90\xc4"
          in
          let derived =
            Utils.Concat_kdf.derive ~z ~keydatalen:128 ~alg_id:"A128GCM"
              ~apu:"QWxpY2U" ~apv:"Qm9i" ()
          in
          let expected_raw =
            "\x56\xaa\x8d\xea\xf8\x23\x6d\x20\x5c\x22\x28\xcd\x71\xa7\x10\x1a"
          in
          Alcotest.(check string)
            "Derived key raw octets match RFC 7518 Appendix C" expected_raw
            derived;
          let b64 = Utils.U_Base64.url_encode_string derived in
          Alcotest.(check string)
            "Derived key base64url matches RFC 7518 Appendix C"
            "VqqN6vgjbSBcIijNcacQGg" b64);
      Alcotest.test_case "Concat KDF without apu and apv" `Quick (fun () ->
          let z =
            "\x9e\x56\xd9\x1d\x81\x71\x35\xd3\x72\x83\x42\x83\xbf\x84\x26\x9c\xfb\x31\x6e\xa3\xda\x80\x6a\x48\xf6\xda\xa7\x79\x8c\xfe\x90\xc4"
          in
          let key =
            Utils.Concat_kdf.derive ~z ~keydatalen:256 ~alg_id:"A256GCM" ()
          in
          Alcotest.(check int)
            "Key length is 32 bytes (256 bits)" 32 (String.length key);
          let key2 =
            Utils.Concat_kdf.derive ~z ~keydatalen:256 ~alg_id:"A256GCM" ()
          in
          Alcotest.(check string) "Derivation is deterministic" key key2);
      Alcotest.test_case "Concat KDF multi-round derivation (reps = 2)" `Quick
        (fun () ->
          let z =
            "\x9e\x56\xd9\x1d\x81\x71\x35\xd3\x72\x83\x42\x83\xbf\x84\x26\x9c\xfb\x31\x6e\xa3\xda\x80\x6a\x48\xf6\xda\xa7\x79\x8c\xfe\x90\xc4"
          in
          let key =
            Utils.Concat_kdf.derive ~z ~keydatalen:512 ~alg_id:"A256CBC-HS512"
              ~apu:"QWxpY2U" ~apv:"Qm9i" ()
          in
          Alcotest.(check int)
            "Key length is 64 bytes (512 bits)" 64 (String.length key);
          let key_first_half = String.sub key 0 32 in
          let key_second_half = String.sub key 32 32 in
          Alcotest.(check bool)
            "Two rounds produce different output" false
            (key_first_half = key_second_half));
      Alcotest.test_case "Concat KDF truncation with 192-bit key" `Quick
        (fun () ->
          let z =
            "\x9e\x56\xd9\x1d\x81\x71\x35\xd3\x72\x83\x42\x83\xbf\x84\x26\x9c\xfb\x31\x6e\xa3\xda\x80\x6a\x48\xf6\xda\xa7\x79\x8c\xfe\x90\xc4"
          in
          let key =
            Utils.Concat_kdf.derive ~z ~keydatalen:192 ~alg_id:"A192KW" ()
          in
          Alcotest.(check int)
            "Key length is 24 bytes (192 bits)" 24 (String.length key));
    ] )

let utils_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "Utils"
    [
      pkcs7_tests;
      u_string_tests;
      u_base64_tests;
      aes_kw_tests;
      concat_kdf_tests;
    ]
