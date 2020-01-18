module RResult = struct
  let map fn r = match r with Ok v -> Ok (fn v) | Error e -> Error e

  let flat_map fn r = match r with Ok v -> fn v | Error e -> Error e

  let to_opt = function Ok v -> Some v | Error _ -> None

  let return v = Ok v

  let both a b =
    match (a, b) with
    | Ok a, Ok b -> Ok (a, b)
    | Error e, _ -> Error e
    | _, Error e -> Error e
end

module ROpt = struct
  let flatten o = match o with Some v -> v | None -> None

  let get_or ~default o = match o with Some v -> v | None -> default
end

module RList = struct
  let filter_map f =
    let rec aux accu = function
      | [] -> List.rev accu
      | x :: l -> (
          match f x with None -> aux accu l | Some v -> aux (v :: accu) l )
    in
    aux []

  let rec find_opt p = function
    | [] -> None
    | x :: l -> if p x then Some x else find_opt p l
end

module RString = struct
  let rev s =
    let len = Astring.String.length s in
    Astring.String.mapi (fun i _ -> s.[len - (i + 1)]) s

  let pad ~c length s =
    let len = Astring.String.length s in
    if len >= length then s
    else
      let diff = length - len in
      Astring.String.v ~len:length (fun i ->
          if i < diff then c else s.[i - diff])

  let trim_leading_null s =
    Astring.String.trim ~drop:(function '\000' -> true | _ -> false) s
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
