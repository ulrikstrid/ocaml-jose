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
    let pad_len = String.get_uint8 cs (cs_len - 1) in
    let data, padding = U_String.split cs (cs_len - pad_len) in
    let rec check idx =
      if idx >= pad_len then true
      else String.get_uint8 padding idx = pad_len && check (idx + 1)
    in
    if check 0 then Ok data else Error (`Msg "bad padding")
end
