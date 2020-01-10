module RResult = struct
  let map fn r = match r with Ok v -> Ok (fn v) | Error e -> Error e

  let map_error fn r = match r with Ok r -> Ok r | Error e -> Error (fn e)

  let flat_map fn r = match r with Ok v -> fn v | Error e -> Error e

  let both a b =
    match (a, b) with
    | Ok a, Ok b -> Ok (a, b)
    | Error e, _ -> Error e
    | _, Error e -> Error e
end

module RList = struct
  let rec find_opt p = function
    | [] -> None
    | x :: l -> if p x then Some x else find_opt p l
end

module RBase64 = struct
  let base64_url_encode =
    Base64.encode ~pad:false ~alphabet:Base64.uri_safe_alphabet

  let base64_url_decode =
    Base64.decode ~pad:false ~alphabet:Base64.uri_safe_alphabet
end

module RJson = struct
  let to_json_string_opt key value =
    match value with Some s -> Some (key, `String s) | None -> None
end
