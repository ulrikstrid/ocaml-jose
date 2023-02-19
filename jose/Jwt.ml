open Utils

type payload = Yojson.Safe.t
type claim = string * Yojson.Safe.t

type error =
  [ `Msg of string
  | `Expired
  | `Not_rsa
  | `Json_parse_failed of string
  | `Unsupported_kty
  | `Invalid_signature ]

let empty_payload = `Assoc []

let payload_to_string payload =
  let serialized_payload = Yojson.Safe.to_string payload in
  U_Base64.url_encode_string serialized_payload

let payload_of_string payload_str =
  let payload = U_Base64.url_decode payload_str in
  U_Result.map Yojson.Safe.from_string payload

type t = {
  header : Header.t;
  raw_header : string;
  payload : payload;
  raw_payload : string;
  signature : Jws.signature;
}

let add_claim (claim_name : string) (claim_value : Yojson.Safe.t)
    (payload : payload) =
  `Assoc ((claim_name, claim_value) :: Yojson.Safe.Util.to_assoc payload)

let get_yojson_claim (jwt : t) (claim_name : string) =
  Yojson.Safe.Util.member claim_name jwt.payload |> Option.some

let get_string_claim (jwt : t) (claim_name : string) =
  Option.bind
    (get_yojson_claim jwt claim_name)
    Yojson.Safe.Util.to_string_option

let get_int_claim (jwt : t) (claim_name : string) =
  Option.bind (get_yojson_claim jwt claim_name) Yojson.Safe.Util.to_int_option

let to_jws (t : t) =
  Jws.
    {
      header = t.header;
      raw_header = t.raw_header;
      signature = t.signature;
      payload = t.raw_payload;
    }

let of_jws (jws : Jws.t) =
  let payload = jws.payload |> Yojson.Safe.from_string in
  {
    header = jws.header;
    raw_header = jws.raw_header;
    signature = jws.signature;
    payload;
    raw_payload = jws.payload;
  }

let to_string ?serialization t =
  let jws = to_jws t in
  Jws.to_string ?serialization jws

let unsafe_of_string token = Jws.of_string token |> U_Result.map of_jws

let check_expiration ~(now : Ptime.t) t =
  let module Json = Yojson.Safe.Util in
  match
    Json.member "exp" t.payload |> Json.to_int_option |> Option.map float_of_int
  with
  | Some exp ->
      let pexp = Ptime.of_float_s exp in
      let is_earlier =
        Option.map (fun pexp -> Ptime.is_earlier now ~than:pexp) pexp
      in

      if is_earlier = Some true then Ok t else Error `Expired
  | None -> Ok t

let validate_signature (type a) ~(jwk : a Jwk.t) (t : t) : (t, 'error) result =
  Jws.validate ~jwk (to_jws t) |> U_Result.map of_jws

let validate (type a) ~(jwk : a Jwk.t) ~now (t : t) : (t, 'error) result =
  match validate_signature ~jwk t with
  | Ok t -> check_expiration t ~now
  | Error e -> Error e

let of_string ~jwk ~now s =
  U_Result.bind (unsafe_of_string s) (validate ~jwk ~now)

let sign ?header ~payload (jwk : Jwk.priv Jwk.t) =
  let header =
    match header with
    | Some header -> header
    | None -> Header.make_header ~typ:"JWT" jwk
  in
  let payload =
    try Ok (Yojson.Safe.to_string payload)
    with _ -> Error (`Msg "Can't serialize payload")
  in
  match payload with
  | Ok payload -> Jws.sign ~header ~payload jwk |> U_Result.map of_jws
  | Error e -> Error e
