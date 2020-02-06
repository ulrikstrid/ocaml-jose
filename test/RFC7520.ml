(* These tests are based on rfc7520, https://tools.ietf.org/html/rfc7520 *)
open Helpers

(* https://tools.ietf.org/html/rfc7520#section-3.3 *)
let rsa_pub_json =
  {|{"kty": "RSA",
"kid": "bilbo.baggins@hobbiton.example",
"use": "sig",
"n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
"e": "AQAB"}|}

(* https://tools.ietf.org/html/rfc7520#section-3.4 *)
let rsa_priv_json =
  {|{"kty": "RSA",
"kid": "bilbo.baggins@hobbiton.example",
"use": "sig",
"n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
"e": "AQAB",
"d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
"p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
"q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
"dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",
"dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
"qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"}|}

(* https://tools.ietf.org/html/rfc7520#section-3.5 *)
let oct_sig_json =
  {|{"kty": "oct",
"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
"use": "sig",
"alg": "HS256",
"k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}|}

(* https://tools.ietf.org/html/rfc7520#section-3.6 *)
let oct_enc_json =
  {|{"kty": "oct",
"kid": "1e571774-2e08-40da-8308-e8d68773842d",
"use": "enc",
"alg": "A256GCM",
"k": "AAPapAv4LbFbiVawEjagUBluYqN5rhna-8nuldDvOx8"}|}

(* https://tools.ietf.org/html/rfc7520#section-4.1 *)
let rsa_jws =
  {|eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg|}

let rsa_jws_header = {|{"alg":"RS256","kid":"bilbo.baggins@hobbiton.example"}|}

let jws_payload =
  "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step \
   onto the road, and if you don't keep your feet, there\xe2\x80\x99s no \
   knowing where you might be swept off to."

let rsa_jws_signature =
  "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg"

let jws_rsa_tests =
  ( "JWS RSA",
    [
      Alcotest.test_case "Can verify jws" `Quick (fun () ->
          let jwk = Jose.Jwk.Pub.of_string rsa_pub_json |> CCResult.get_exn in
          let jws = Jose.Jws.of_string rsa_jws in
          let validated_jws = CCResult.flat_map (Jose.Jws.validate ~jwk) jws in
          check_result_string "correct payload" (Ok jws_payload)
            (CCResult.map (fun jws -> Jose.Jws.(jws.payload)) validated_jws);
          check_result_string "correct signature" (Ok rsa_jws_signature)
            (CCResult.map (fun jws -> Jose.Jws.(jws.signature)) validated_jws);
          check_result_string "correct header" (Ok rsa_jws_header)
            (CCResult.map
               (fun jws ->
                 Jose.Jws.(jws.header)
                 |> Jose.Header.to_json |> Yojson.Safe.to_string)
               validated_jws));
      Alcotest.test_case "Generates the same JWS" `Quick (fun () ->
          let jwk =
            Jose.Jwk.Priv.of_string rsa_priv_json
            |> CCResult.map_err (fun (`Msg e) -> `Msg ("JWK: " ^ e))
          in
          let header =
            Jose.Header.of_json @@ Yojson.Safe.from_string rsa_jws_header
            |> CCResult.map_err (fun (`Msg e) -> `Msg ("header: " ^ e))
          in
          let jws =
            CCResult.both jwk header
            |> CCResult.flat_map (fun (jwk, header) ->
                   Jose.Jws.sign ~header ~payload:jws_payload jwk)
          in
          check_result_string "correct jws string" (Ok rsa_jws)
            (CCResult.flat_map Jose.Jws.to_string jws));
    ] )

(* https://tools.ietf.org/html/rfc7520#section-4.4 *)
let oct_jws =
  {|eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0|}

let oct_jws_header =
  {|{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"}|}

let oct_jws_signature = "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"

let jws_oct_tests =
  ( "JWS oct",
    [
      Alcotest.test_case "Can verify jws" `Quick (fun () ->
          let jwk = Jose.Jwk.Pub.of_string oct_sig_json |> CCResult.get_exn in
          let jws = Jose.Jws.of_string oct_jws in
          let validated_jws = CCResult.flat_map (Jose.Jws.validate ~jwk) jws in
          check_result_string "correct payload" (Ok jws_payload)
            (CCResult.map (fun jws -> Jose.Jws.(jws.payload)) validated_jws);
          check_result_string "correct signature" (Ok oct_jws_signature)
            (CCResult.map (fun jws -> Jose.Jws.(jws.signature)) validated_jws);
          check_result_string "correct header" (Ok oct_jws_header)
            (CCResult.map
               (fun jws ->
                 Jose.Jws.(jws.header)
                 |> Jose.Header.to_json |> Yojson.Safe.to_string)
               validated_jws));
      Alcotest.test_case "Generates the same JWS" `Quick (fun () ->
          let jwk =
            Jose.Jwk.Priv.of_string oct_sig_json
            |> CCResult.map_err (fun (`Msg e) -> `Msg ("JWK: " ^ e))
          in
          let header =
            Jose.Header.of_json @@ Yojson.Safe.from_string oct_jws_header
            |> CCResult.map_err (fun (`Msg e) -> `Msg ("header: " ^ e))
          in
          let jws =
            CCResult.both jwk header
            |> CCResult.flat_map (fun (jwk, header) ->
                   Jose.Jws.sign ~header ~payload:jws_payload jwk)
          in
          check_result_string "correct jws string" (Ok oct_jws)
            (CCResult.flat_map Jose.Jws.to_string jws));
    ] )

(* Begin tests *)
let rfc_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7520"
    [ jws_rsa_tests; jws_oct_tests ]

let suite = rfc_suite
