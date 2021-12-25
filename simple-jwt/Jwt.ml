type payload = Yojson.Safe.t

let make ~payload ~jwk =
  let header = Jose.Header.make_header jwk in
  Jose.Jwt.sign ~header ~payload jwk |> Result.get_ok |> Jose.Jwt.to_string

let validate ~token ~jwk =
  match Result.bind (Jose.Jwt.of_string token) (Jose.Jwt.validate ~jwk) with
  | Ok jwt -> Some jwt.payload
  | Error _ -> None

let make_jwk ?(kind=`Key) key =
  match kind with
  | `Key -> Jose.Jwk.make_oct key
  | `PEM -> Jose.Jwk.of_priv_pem key
  | `JSON -> Jose.Jwk.of_priv_json key