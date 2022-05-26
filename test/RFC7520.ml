(* These tests are based on rfc7520, https://tools.ietf.org/html/rfc7520 *)
open Helpers

(* https://tools.ietf.org/html/rfc7520#section-3.1 *)
let ec_pub_json =
  {|{"kty": "EC",
"kid": "bilbo.baggins@hobbiton.example",
"use": "sig",
"crv": "P-521",
"x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
"y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"}|}

(* https://tools.ietf.org/html/rfc7520#section-3.1 *)
let ec_priv_sig_json =
  {|{"kty": "EC",
"kid": "bilbo.baggins@hobbiton.example",
"use": "sig",
"crv": "P-521",
"x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
"y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
"d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"}|}

(* https://tools.ietf.org/html/rfc7520#section-3.3 *)
let rsa_pub_json =
  {|{"kty": "RSA",
"kid": "bilbo.baggins@hobbiton.example",
"use": "sig",
"n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
"e": "AQAB"}|}

(* https://tools.ietf.org/html/rfc7520#section-3.4 *)
let rsa_priv_sig_json =
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

let jws_payload =
  "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step \
   onto the road, and if you don't keep your feet, there\xe2\x80\x99s no \
   knowing where you might be swept off to."

let jwe_payload =
  "You can trust us to stick with you through thick and thin\xe2\x80\x93to the \
   bitter end. And you can trust us to keep any secret of \
   yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us \
   to let you face trouble alone, and go off without a word. We are your \
   friends, Frodo."

(* https://tools.ietf.org/html/rfc7520#section-4.1 *)
let rsa_jws =
  {|eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg|}

let rsa_jws_header = {|{"alg":"RS256","kid":"bilbo.baggins@hobbiton.example"}|}

let rsa_jws_signature =
  "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg"

let jws_rsa_tests =
  ( "JWS RSA",
    [
      Alcotest.test_case "Can verify jws" `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_pub_json_string rsa_pub_json |> CCResult.get_exn
          in
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
          let jwk = Jose.Jwk.of_priv_json_string rsa_priv_sig_json in
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
            (CCResult.map Jose.Jws.to_string jws));
    ] )

(* https://tools.ietf.org/html/rfc7520#section-4.3 *)

let ecdsa_jws_header =
  {|{"alg":"ES512","kid":"bilbo.baggins@hobbiton.example"}|}

let ecdsa_jws_header_base64 =
  "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9"

let ecdsa_jws_payload_base64 =
  "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"

let ecdsa_jws_signature_base64 =
  "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"

let ecdsa_jws =
  Printf.sprintf "%s.%s.%s" ecdsa_jws_header_base64 ecdsa_jws_payload_base64
    ecdsa_jws_signature_base64

let jws_ecdsa_tests =
  ( "JWS ECDSA",
    [
      Alcotest.test_case "Can verify jws" `Quick (fun () ->
          let () = print_endline ecdsa_jws in
          let jwk =
            Jose.Jwk.of_pub_json_string ec_pub_json
            |> CCResult.map_err (function
                 | `Msg m ->
                     print_endline m;
                     `Msg m
                 | `Json_parse_failed m ->
                     print_endline m;
                     `Json_parse_failed m
                 | `Unsupported_kty ->
                     print_endline "Unsupported_kty";
                     `Unsupported_kty
                 | x -> x)
            |> CCResult.get_exn
          in
          let jws = Jose.Jws.of_string ecdsa_jws in
          let validated_jws = CCResult.flat_map (Jose.Jws.validate ~jwk) jws in
          check_result_string "correct payload" (Ok jws_payload)
            (CCResult.map (fun jws -> Jose.Jws.(jws.payload)) validated_jws);
          check_result_string "correct signature"
            (Ok ecdsa_jws_signature_base64)
            (CCResult.map (fun jws -> Jose.Jws.(jws.signature)) validated_jws);
          check_result_string "correct header" (Ok ecdsa_jws_header)
            (CCResult.map
               (fun jws ->
                 Jose.Jws.(jws.header)
                 |> Jose.Header.to_json |> Yojson.Safe.to_string)
               validated_jws))
      (*
       * Disabled until https://github.com/mirage/mirage-crypto/issues/105 is solved
      Alcotest.test_case "Generates the same JWS" `Quick (fun () ->
          let jwk = Jose.Jwk.of_priv_json_string ec_priv_sig_json in
          let header =
            Jose.Header.of_json @@ Yojson.Safe.from_string ecdsa_jws_header
            |> CCResult.map_err (fun (`Msg e) -> `Msg ("header: " ^ e))
          in
          let jws =
            CCResult.both jwk header
            |> CCResult.flat_map (fun (jwk, header) ->
                   Jose.Jws.sign ~header ~payload:jws_payload jwk)
          in
          check_result_string "correct jws string" (Ok ecdsa_jws)
            (CCResult.map Jose.Jws.to_string jws));
       *);
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
          let jwk =
            Jose.Jwk.of_pub_json_string oct_sig_json |> CCResult.get_exn
          in
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
          let jwk = Jose.Jwk.of_priv_json_string oct_sig_json in
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
            (CCResult.map Jose.Jws.to_string jws));
    ] )

let rsa_priv_enc_json_5_1 =
  {|{"kty": "RSA",
"kid": "frodo.baggins@hobbiton.example",
"use": "enc",
"n": "maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegTHVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5UNwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4cR5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oypBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYAVotGlvMQ",
"e": "AQAB",
"d": "Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wybQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PNmiuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2vpzj85bQQ",
"p": "2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaEoekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ2VFmU",
"q": "te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_VF099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8d6Et0",
"dp": "UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTHQmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JVRDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsflo0rYU",
"dq": "iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9MbpFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87ACfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14TkXlHE",
"qi": "kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZlXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx2bQ_mM"}|}

let rsa_priv_enc_json_5_2 =
  {|{"kty": "RSA",
"kid": "samwise.gamgee@hobbiton.example",
"use": "enc",
"n": "wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRrI4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-FyXJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnkNrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeStsqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIUe7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBODFskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqBSAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhOOnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDaiCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnTyC0xhWBlsolZE",
"e": "AQAB",
"alg": "RSA-OAEP",
"d": "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9EA-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIjh1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r-MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yDF-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1LoomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W_IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c9WsWgRzI-K8gE",
"p": "7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKghvM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsYa_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3mY46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9sfbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgPgWCv5HoQ",
"q": "zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6ZyKQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDcqssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYGRuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJaPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EXe2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJJlXXnH8Q",
"dp": "19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xnx5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQJ_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72FZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3iXjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGmpKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9LcnwwT0jvoQ",
"dq": "S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fgdyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrIChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iznBNCeOUIQ",
"qi": "FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCciRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMwQqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq8EzqZEKIA"}|}

(* Key Encryption Using RSA v1.5 and AES-HMAC-SHA2 *)
let jwe_aes_hmac_sha2_5_1 =
  "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePFvG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2GXfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcGTSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8VlzNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOhMBs9M8XL223Fg47xlGsMXdfuY-4jaqVw.bbd5sTkYwhAIqfHsx8DayA.0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_raa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8OWzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZVyeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VWi7lzA6BP430m.kvKuFBXHe5mQr4lqgobAUg"

let jwe_rsa_oaep_aes_gcm_5_2 =
  "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0.rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQibeYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyucvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8BpxKdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pKIIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQfOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe38UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDRs.-nBoKLH0YkLZPSI9.o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgRL-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEwP7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSVmaPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw.UCGiqJxhBI3IFVdPalHHvA"

let jwe_rsa_tests =
  ( "JWE RSA",
    [
      Alcotest.test_case "Can encrypt a JWE Using RSA v1.5 and AES-HMAC-SHA2"
        `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_enc_json_5_1
            |> CCResult.get_exn
          in
          let jwe =
            Jose.Jwe.decrypt jwe_aes_hmac_sha2_5_1 ~jwk |> CCResult.get_exn
          in
          let str = Jose.Jwe.encrypt ~jwk jwe |> CCResult.get_exn in
          let jwe2 = Jose.Jwe.decrypt ~jwk str in
          check_result_string "Has the same payload after roundtrip"
            (Ok jwe.payload)
            (CCResult.map (fun (j : Jose.Jwe.t) -> j.payload) jwe2);
          check_result_string "Has the same cek after roundtrip" (Ok jwe.cek)
            (CCResult.map (fun (j : Jose.Jwe.t) -> j.cek) jwe2);
          check_result_string "Has the same iv after roundtrip" (Ok jwe.iv)
            (CCResult.map (fun (j : Jose.Jwe.t) -> j.iv) jwe2));
      Alcotest.test_case "Can encrypt a JWE Using RSA-OAEP with AES-GCM" `Quick
        (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_enc_json_5_2
            |> CCResult.get_exn
          in
          let jwe =
            Jose.Jwe.decrypt jwe_rsa_oaep_aes_gcm_5_2 ~jwk |> CCResult.get_exn
          in
          let str = Jose.Jwe.encrypt ~jwk jwe |> CCResult.get_exn in
          let jwe2 = Jose.Jwe.decrypt ~jwk str in
          check_result_string "Has the same payload after roundtrip"
            (Ok jwe.payload)
            (CCResult.map (fun (j : Jose.Jwe.t) -> j.payload) jwe2);
          check_result_string "Has the same cek after roundtrip" (Ok jwe.cek)
            (CCResult.map (fun (j : Jose.Jwe.t) -> j.cek) jwe2);
          check_result_string "Has the same iv after roundtrip" (Ok jwe.iv)
            (CCResult.map (fun (j : Jose.Jwe.t) -> j.iv) jwe2));
      Alcotest.test_case "Can decrypt a JWE Using RSA v1.5 and AES-HMAC-SHA2"
        `Quick (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_enc_json_5_1
            |> CCResult.get_exn
          in
          let jwe = Jose.Jwe.decrypt jwe_aes_hmac_sha2_5_1 ~jwk in
          check_result_string "correct kid in header"
            (Ok "frodo.baggins@hobbiton.example")
            (CCResult.map
               (fun jwe ->
                 jwe.Jose.Jwe.header.kid |> CCOption.get_exn_or "fail")
               jwe);
          check_result_string "correct alg in header" (Ok "RSA1_5")
            (CCResult.map
               (fun jwe -> Jose.Jwa.alg_to_string jwe.Jose.Jwe.header.alg)
               jwe);
          check_result_string "correct enc in header" (Ok "A128CBC-HS256")
            (CCResult.map
               (fun jwe ->
                 match jwe.Jose.Jwe.header.enc with
                 | None -> "none"
                 | Some x -> Jose.Jwa.enc_to_string x)
               jwe);
          check_result_string "correct initialization vector"
            (Ok "bbd5sTkYwhAIqfHsx8DayA")
            (CCResult.map
               (fun jwe ->
                 jwe.Jose.Jwe.iv
                 |> Base64.encode_string ~pad:false
                      ~alphabet:Base64.uri_safe_alphabet)
               jwe);
          check_result_string "correct Content Encryption Key"
            (Ok "3qyTVhIWt5juqZUCpfRqpvauwB956MEJL2Rt-8qXKSo")
            (CCResult.map
               (fun jwe ->
                 jwe.Jose.Jwe.cek
                 |> Base64.encode_string ~pad:false
                      ~alphabet:Base64.uri_safe_alphabet)
               jwe);
          check_result_string "correct payload" (Ok jwe_payload)
            (CCResult.map (fun jwe -> jwe.Jose.Jwe.payload) jwe));
      Alcotest.test_case "Can decrypt a JWE Using RSA-OAEP with AES-GCM" `Quick
        (fun () ->
          let jwk =
            Jose.Jwk.of_priv_json_string rsa_priv_enc_json_5_2
            |> CCResult.get_exn
          in
          let jwe = Jose.Jwe.decrypt jwe_rsa_oaep_aes_gcm_5_2 ~jwk in
          check_result_string "correct kid in header"
            (Ok "samwise.gamgee@hobbiton.example")
            (CCResult.map
               (fun jwe ->
                 jwe.Jose.Jwe.header.kid |> CCOption.get_exn_or "fail")
               jwe);
          check_result_string "correct alg in header" (Ok "RSA-OAEP")
            (CCResult.map
               (fun jwe -> Jose.Jwa.alg_to_string jwe.Jose.Jwe.header.alg)
               jwe);
          check_result_string "correct enc in header" (Ok "A256GCM")
            (CCResult.map
               (fun jwe ->
                 match jwe.Jose.Jwe.header.enc with
                 | None -> "none"
                 | Some x -> Jose.Jwa.enc_to_string x)
               jwe);
          check_result_string "correct initialization vector"
            (Ok "-nBoKLH0YkLZPSI9")
            (CCResult.map
               (fun jwe ->
                 jwe.Jose.Jwe.iv
                 |> Base64.encode_string ~pad:false
                      ~alphabet:Base64.uri_safe_alphabet)
               jwe);
          check_result_string "correct Content Encryption Key"
            (Ok "mYMfsggkTAm0TbvtlFh2hyoXnbEzJQjMxmgLN3d8xXA")
            (CCResult.map
               (fun jwe ->
                 jwe.Jose.Jwe.cek
                 |> Base64.encode_string ~pad:false
                      ~alphabet:Base64.uri_safe_alphabet)
               jwe);
          check_result_string "correct payload" (Ok jwe_payload)
            (CCResult.map (fun jwe -> jwe.Jose.Jwe.payload) jwe));
    ] )

(* Begin tests *)
let rfc_suite, _ =
  Junit_alcotest.run_and_report ~package:"jose" "RFC7520"
    [ jws_rsa_tests; jws_ecdsa_tests; jws_oct_tests; jwe_rsa_tests ]

let suite = rfc_suite
