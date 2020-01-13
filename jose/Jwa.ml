type kty = [ `oct | `RSA | `EC ]

let kty_to_string = function `oct -> "oct" | `RSA -> "RSA" | `EC -> "EC"

let kty_of_string = function
  | "oct" -> `oct
  | "RSA" -> `RSA
  | "EC" -> `EC
  | _ -> `RSA

type alg = [ `RS256 | `HS256 | `none | `Unknown ]

let alg_to_string = function
  | `RS256 -> "RS256"
  | `HS256 -> "HS256"
  | `none -> "none"
  | _ -> "unknown"

let alg_of_string = function
  | "RS256" -> `RS256
  | "HS256" -> `HS256
  | "none" -> `none
  | _ -> `Unknown

let alg_to_json alg = `String (alg_to_string alg)

let alg_of_json alg = Yojson.Safe.Util.to_string alg |> alg_of_string
