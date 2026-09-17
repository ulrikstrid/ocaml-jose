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
    let len = String.length plaintext in
    let kek_len = String.length kek in
    if kek_len <> 16 && kek_len <> 24 && kek_len <> 32 then
      Error (`Msg "Bad KEK length, must be 16, 24, or 32 bytes")
    else if len >= 16 && len mod 8 = 0 then (
      (* 1) Initialize variables: A = IV, R[i] = P[i] *)
      let key = Mirage_crypto.AES.ECB.of_secret kek in
      let n = len / 8 in

      (* 1) Initialize variables: C[0] = IV, C[1..n] = P[1..n] *)
      let out = Bytes.create (len + 8) in
      Bytes.blit_string default_iv 0 out 0 8;
      Bytes.blit_string plaintext 0 out 8 len;
      let b_in = Bytes.create 16 in
      let b_out = Bytes.create 16 in

      (* 2) Calculate intermediate values: 6 rounds (j = 0..5, i = 0..n-1) *)
      for j = 0 to 5 do
        for i = 1 to n do
          (* t = (n * j) + i, 1-indexed step counter *)
          let t = (n * j) + i in
          (* B = AES(K, A | R[i]) *)
          Bytes.blit out 0 b_in 0 8;
          Bytes.blit out (8 * i) b_in 8 8;
          Mirage_crypto.AES.ECB.encrypt_into ~key
            (Bytes.unsafe_to_string b_in)
            ~src_off:0 b_out ~dst_off:0 16;

          (* A = MSB(64, B) ^ t *)
          Int64.logxor (Bytes.get_int64_be b_out 0) (Int64.of_int t)
          |> Bytes.set_int64_be out 0;

          (* R[i] = LSB(64, B) *)
          Bytes.blit b_out 8 out (8 * i) 8
        done
      done;
      (* 3) Output results: C[0] = A, C[i] = R[i] *)
      String.of_bytes out |> Result.ok)
    else
      Error
        (`Msg
           "Bad plaintext length, must be multiple of 8 and at least 16 bytes \
            long")

  (** RFC 3394 Section 2.2.2: Key Unwrap *)
  let unwrap ~kek ciphertext =
    let kek_len = String.length kek in
    let len = String.length ciphertext in
    if kek_len <> 16 && kek_len <> 24 && kek_len <> 32 then
      Error (`Msg "Bad KEK length, must be 16, 24, or 32 bytes")
    else if len >= 24 && len mod 8 = 0 then (
      (* 1) Initialize variables: A = C[0], R[i] = C[i] *)
      let key = Mirage_crypto.AES.ECB.of_secret kek in
      let n = (len / 8) - 1 in

      let out = Bytes.of_string ciphertext in
      let b_in = Bytes.create 16 in
      let b_out = Bytes.create 16 in

      (* 2) Calculate intermediate values in reverse (j = 5..0, i = n-1..0) *)
      for j = 5 downto 0 do
        for i = n downto 1 do
          let t = (n * j) + i in

          (* A' = A ^ t *)
          Int64.logxor (Bytes.get_int64_be out 0) (Int64.of_int t)
          |> Bytes.set_int64_be b_in 0;

          (* Copy R[i] into second half of AES block *)
          Bytes.blit out (8 * i) b_in 8 8;

          (* B = AES-1(K, (A ^ t) | R[i]) *)
          Mirage_crypto.AES.ECB.decrypt_into ~key
            (Bytes.unsafe_to_string b_in)
            ~src_off:0 b_out ~dst_off:0 16;

          (* A = MSB(64, B) *)
          Bytes.blit b_out 0 out 0 8;

          (* R[i] = LSB(64, B) *)
          Bytes.blit b_out 8 out (8 * i) 8
        done
      done;
      (* 3) Output results: check if A == IV, then output P[i] = R[i] *)
      if Eqaf.equal (Bytes.sub_string out 0 8) default_iv then
        Bytes.sub_string out 8 (n * 8) |> Result.ok
      else Error (`Msg "Integrity check failed"))
    else
      Error
        (`Msg
           "Bad ciphertext length, must be multiple of 8 and at least 24 bytes \
            long")
end

module Concat_kdf = struct
  (** Concatenation Key Derivation Function (Concat KDF)
      - RFC 7518 Section 4.6.2: Key Derivation for ECDH Key Agreement
      - NIST SP 800-56A Section 5.8.1: Concatenation Key Derivation Function
      - RFC 7518 Appendix C: Example ECDH-ES Key Agreement Computation *)

  (** 32-bit big-endian integer encoding (NIST SP 800-56A Section 5.8.1) *)
  let int32_to_be n =
    let b = Bytes.create 4 in
    Bytes.set_int32_be b 0 (Int32.of_int n);
    Bytes.unsafe_to_string b

  (** RFC 7518 Section 4.6.2: Construct OtherInfo parameter *)
  let make_other_info ~alg_id ?apu ?apv keydatalen =
    (* AlgorithmID: Datalen (32-bit BE) || Data ("enc" or "alg") *)
    let alg_info = int32_to_be (String.length alg_id) ^ alg_id in
    (* PartyUInfo: Datalen (32-bit BE) || Data (base64url-decoded "apu", or 4 null bytes if absent) *)
    let u_info =
      match apu with
      | Some u -> (
          match U_Base64.url_decode u with
          | Ok raw -> int32_to_be (String.length raw) ^ raw
          | Error _ -> int32_to_be 0)
      | None -> int32_to_be 0
    in
    (* PartyVInfo: Datalen (32-bit BE) || Data (base64url-decoded "apv", or 4 null bytes if absent) *)
    let v_info =
      match apv with
      | Some v -> (
          match U_Base64.url_decode v with
          | Ok raw -> int32_to_be (String.length raw) ^ raw
          | Error _ -> int32_to_be 0)
      | None -> int32_to_be 0
    in
    (* SuppPubInfo: 32-bit big-endian keydatalen (in bits) *)
    let supp_pub = int32_to_be keydatalen in
    (* OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
       (SuppPrivInfo is the empty octet sequence) *)
    String.concat "" [ alg_info; u_info; v_info; supp_pub ]

  (** RFC 7518 Section 4.6.2 & NIST SP 800-56A Section 5.8.1: Key derivation *)
  let derive ~z ~keydatalen ~alg_id ?apu ?apv () =
    (* reps = ceil(keydatalen / hashlen), where hashlen = 256 for SHA-256 *)
    let reps = (keydatalen + 255) / 256 in
    let other_info = make_other_info ~alg_id ?apu ?apv keydatalen in
    if reps = 1 then
      (* Single round: K(1) = SHA-256(0x00000001 || z || OtherInfo) *)
      let d =
        Digestif.SHA256.digest_string (int32_to_be 1 ^ z ^ other_info)
        |> Digestif.SHA256.to_raw_string
      in
      (* DerivedKey: leading keydatalen / 8 octets *)
      if keydatalen = 256 then d else String.sub d 0 (keydatalen / 8)
    else
      (* Multi-round derivation: K(i) = SHA-256(counter(i) || z || OtherInfo) *)
      let rec loop i acc =
        if i > reps then String.concat "" (List.rev acc)
        else
          (* 32-bit big-endian round counter i *)
          let counter = int32_to_be i in
          (* K(i) = SHA-256(counter || z || OtherInfo) *)
          let d =
            Digestif.SHA256.digest_string (counter ^ z ^ other_info)
            |> Digestif.SHA256.to_raw_string
          in
          loop (i + 1) (d :: acc)
      in
      (* Full derived octet stream: K(1) || ... || K(reps) *)
      let full = loop 1 [] in
      (* DerivedKey: leading keydatalen / 8 octets *)
      String.sub full 0 (keydatalen / 8)
end
