module U_Result = struct
  let all8 a b c d e f g h =
    match (a, b, c, d, e, f, g, h) with
    | Ok a, Ok b, Ok c, Ok d, Ok e, Ok f, Ok g, Ok h ->
        Ok (a, b, c, d, e, f, g, h)
    | _ -> Error (`Msg "all 8 was not Ok")
end

module U_String = struct
  let rev s =
    let len = String.length s in
    String.mapi (fun i _ -> s.[len - (i + 1)]) s

  let pad ~c ~len:pad_length s =
    let len = String.length s in
    if len >= pad_length then s
    else
      let diff = pad_length - len in
      Astring.String.v ~len:pad_length (fun i ->
          if i < diff then c else s.[i - diff])

  let trim_leading_null s =
    Astring.String.trim ~drop:(function '\000' -> true | _ -> false) s

  let split s len =
    (String.sub s 0 len, String.sub s len (String.length s - len))
end

module U_Base64 = struct
  let url_encode_string ?(pad = false) payload =
    Base64.encode_string ~pad ~alphabet:Base64.uri_safe_alphabet payload

  let url_encode ?(pad = false) ?off ?len payload =
    Base64.encode ~pad ~alphabet:Base64.uri_safe_alphabet ?off ?len payload

  let url_decode ?(pad = false) ?off ?len payload =
    Base64.decode ~pad ~alphabet:Base64.uri_safe_alphabet ?off ?len payload
end

module RJson = struct
  let to_json_string_opt key value =
    match value with Some s -> Some (key, `String s) | None -> None
end

module Pkcs7 = struct
  (* https://tools.ietf.org/html/rfc5652#section-6.3 *)
  let pad data block_size =
    let pad_size = block_size - (String.length data mod block_size) in
    if pad_size = 0 then data
    else
      (* this is the remaining bytes in the last block *)
      let pad =
        let c = Char.chr (pad_size land 0xff) in
        Bytes.init pad_size (Fun.const c)
      in
      (* fills the pad buffer with bytes each containing "pad_size" as value *)
      (* TODO(anmonteiro): allocate a single bytes and blit + set chars *)
      data ^ Bytes.to_string pad

  let unpad cs =
    let cs_len = String.length cs in
    if cs_len = 0 then Error (`Msg "bad padding")
    else
      let pad_len = String.get_uint8 cs (cs_len - 1) in
      if pad_len = 0 || pad_len > cs_len then Error (`Msg "bad padding")
      else
        let data, padding = U_String.split cs (cs_len - pad_len) in
        let rec check idx =
          if idx >= pad_len then true
          else String.get_uint8 padding idx = pad_len && check (idx + 1)
        in
        if check 0 then Ok data else Error (`Msg "bad padding")
end

module Aes_kw = struct
  (** Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) *)

  (** RFC 3394 Section 2.2.3.1: Default Initial Value (IV = 0xA6A6A6A6A6A6A6A6)
  *)
  let default_iv = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6"

  (** RFC 3394 Section 2.2.1: Key Wrap *)
  let wrap ~kek (plaintext : string) : (string, [> `Msg of string ]) result =
    let bytes = Bytes.of_string plaintext in
    let len = Bytes.length bytes in
    let kek_len = String.length kek in
    if kek_len <> 16 && kek_len <> 24 && kek_len <> 32 then
      Error (`Msg "Bad KEK length, must be 16, 24, or 32 bytes")
    else if len >= 16 && len mod 8 = 0 then
      (* 1) Initialize variables: A = IV, R[i] = P[i] *)
      let key = Mirage_crypto.AES.ECB.of_secret kek in
      let a = Bytes.of_string default_iv in
      let n = len / 8 in
      let r = ArrayLabels.init ~f:(fun i -> Bytes.sub bytes (8 * i) 8) n in
      let () =
        (* 2) Calculate intermediate values: 6 rounds (j = 0..5, i = 0..n-1) *)
        for j = 0 to 5 do
          ArrayLabels.mapi_inplace
            ~f:(fun i c ->
              (* t = (n * j) + i, 1-indexed step counter *)
              let t = (n * j) + i + 1 in
              (* B = AES(K, A | R[i]) *)
              let block = Bytes.cat a c in
              let b =
                Mirage_crypto.AES.ECB.encrypt ~key (String.of_bytes block)
                |> Bytes.of_string
              in
              (* A = MSB(64, B) ^ t *)
              let left = Bytes.sub b 0 8 in
              Int64.logxor (Bytes.get_int64_be left 0) (Int64.of_int t)
              |> Bytes.set_int64_be left 0;
              Bytes.blit left 0 a 0 8;

              (* R[i] = LSB(64, B) *)
              let right = Bytes.sub b 8 8 in
              right)
            r
        done
      in
      (* 3) Output results: C[0] = A, C[i] = R[i] *)
      Bytes.concat Bytes.empty (a :: Array.to_list r)
      |> String.of_bytes |> Result.ok
    else
      Error
        (`Msg
           "Bad plaintext length, must be multiple of 8 and at least 16 bytes \
            long")

  (** RFC 3394 Section 2.2.2: Key Unwrap *)
  let unwrap ~kek ciphertext =
    let kek_len = String.length kek in
    let bytes = Bytes.of_string ciphertext in
    let len = Bytes.length bytes in
    if kek_len <> 16 && kek_len <> 24 && kek_len <> 32 then
      Error (`Msg "Bad KEK length, must be 16, 24, or 32 bytes")
    else if len >= 24 && len mod 8 = 0 then
      (* 1) Initialize variables: A = C[0], R[i] = C[i] *)
      let key = Mirage_crypto.AES.ECB.of_secret kek in
      let n = (len / 8) - 1 in
      let a = Bytes.sub bytes 0 8 in
      let r =
        ArrayLabels.init ~f:(fun i -> Bytes.sub bytes ((8 * i) + 8) 8) n
      in
      let () =
        (* 2) Calculate intermediate values in reverse (j = 5..0, i = n-1..0) *)
        for j = 5 downto 0 do
          for i = n - 1 downto 0 do
            let c = Array.get r i in
            let t = (n * j) + i + 1 in

            (* A' = A ^ t *)
            Int64.logxor (Bytes.get_int64_be a 0) (Int64.of_int t)
            |> Bytes.set_int64_be a 0;

            (* B = AES-1(K, (A ^ t) | R[i]) *)
            let block = Bytes.cat a c in
            let b =
              Mirage_crypto.AES.ECB.decrypt ~key (String.of_bytes block)
              |> Bytes.of_string
            in

            (* A = MSB(64, B), R[i] = LSB(64, B) *)
            let left = Bytes.sub b 0 8 in
            Bytes.blit left 0 a 0 8;
            let right = Bytes.sub b 8 8 in

            Array.set r i right
          done
        done
      in
      (* 3) Output results: check if A == IV, then output P[i] = R[i] *)
      if Eqaf.equal (String.of_bytes a) default_iv then
        Bytes.concat Bytes.empty (Array.to_list r)
        |> String.of_bytes |> Result.ok
      else Error (`Msg "Integrity check failed")
    else
      Error
        (`Msg
           "Bad ciphertext length, must be multiple of 8 and at least 24 bytes \
            long")
end

module Concat_kdf = struct
  let int32_to_be n =
    let b = Bytes.create 4 in
    Bytes.set_int32_be b 0 (Int32.of_int n);
    Bytes.unsafe_to_string b

  let make_other_info ~alg_id ?apu ?apv keydatalen =
    let alg_info = int32_to_be (String.length alg_id) ^ alg_id in
    let u_info =
      match apu with
      | Some u -> (
          match U_Base64.url_decode u with
          | Ok raw -> int32_to_be (String.length raw) ^ raw
          | Error _ -> int32_to_be 0)
      | None -> int32_to_be 0
    in
    let v_info =
      match apv with
      | Some v -> (
          match U_Base64.url_decode v with
          | Ok raw -> int32_to_be (String.length raw) ^ raw
          | Error _ -> int32_to_be 0)
      | None -> int32_to_be 0
    in
    let supp_pub = int32_to_be keydatalen in
    String.concat "" [ alg_info; u_info; v_info; supp_pub ]

  let derive ~z ~keydatalen ~alg_id ?apu ?apv () =
    let reps = (keydatalen + 255) / 256 in
    let other_info = make_other_info ~alg_id ?apu ?apv keydatalen in
    if reps = 1 then
      let d =
        Digestif.SHA256.digest_string (int32_to_be 1 ^ z ^ other_info)
        |> Digestif.SHA256.to_raw_string
      in
      if keydatalen = 256 then d else String.sub d 0 (keydatalen / 8)
    else
      let rec loop i acc =
        if i > reps then String.concat "" (List.rev acc)
        else
          let counter = int32_to_be i in
          let d =
            Digestif.SHA256.digest_string (counter ^ z ^ other_info)
            |> Digestif.SHA256.to_raw_string
          in
          loop (i + 1) (d :: acc)
      in
      let full = loop 1 [] in
      String.sub full 0 (keydatalen / 8)
end
