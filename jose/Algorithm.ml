type t = [ `RS256 | `none | `Unknown ]

let to_json alg =
  (match alg with `RS256 -> "RS256" | `none -> "none" | _ -> "unknown")
  |> fun a -> `String a

let of_json alg =
  Yojson.Safe.Util.to_string alg |> function
  | "RS256" -> `RS256
  | "none" -> `none
  | _ -> `Unknown
