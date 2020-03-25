type kty = [ `oct | `RSA | `EC | `Unsupported of string ]

let kty_to_string = function
  | `oct -> "oct"
  | `RSA -> "RSA"
  | `EC -> "EC"
  | `Unsupported str -> str

let kty_of_string = function
  | "oct" -> `oct
  | "RSA" -> `RSA
  | "EC" -> `EC
  | str -> `Unsupported str

type alg = [ `RS256 | `HS256 | `none | `Unsupported of string ]

let alg_to_string = function
  | `RS256 -> "RS256"
  | `HS256 -> "HS256"
  | `none -> "none"
  | `Unsupported string -> string

let alg_of_string = function
  | "RS256" -> `RS256
  | "HS256" -> `HS256
  | "none" -> `none
  | str -> `Unsupported str

let alg_to_json alg = `String (alg_to_string alg)

let alg_of_json alg = Yojson.Safe.Util.to_string alg |> alg_of_string

type enc =
  [ `A128CBC_HS256
  | `A256CBC_HS512
  | `A128GCM
  | `A256GCM
  | `Unsupported of string ]

let enc_to_string = function
  | `A128CBC_HS256 -> "A128CBC-HS256"
  | `A256CBC_HS512 -> "A256CBC-HS512"
  | `A128GCM -> "A128GCM"
  | `A256GCM -> "A256GCM"
  | `Unsupported str -> str

let enc_of_string = function
  | "A128CBC-HS256" -> `A128CBC_HS256
  | "A256CBC-HS512" -> `A256CBC_HS512
  | "A128GCM" -> `A128GCM
  | "A256GCM" -> `A256GCM
  | str -> `Unsupported str

let enc_to_length = function
  | `A128CBC_HS256 -> 256
  | `A256CBC_HS512 -> 512
  | `A128GCM -> 128
  | `A256GCM -> 256
  | `Unsupported _ -> 0

let enc_to_json enc = `String (enc_to_string enc)

let enc_of_json enc = Yojson.Safe.Util.to_string enc |> enc_of_string
