type t = [ `RS256 | `HS256 | `none | `Unknown ]

let to_string = function
  | `RS256 -> "RS256"
  | `HS256 -> "HS256"
  | `none -> "none"
  | _ -> "unknown"

let of_string = function
  | "RS256" -> `RS256
  | "HS256" -> `HS256
  | "none" -> `none
  | _ -> `Unknown

let to_json alg = `String (to_string alg)

let of_json alg = Yojson.Safe.Util.to_string alg |> of_string
