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
  RBase64.url_encode_string serialized_payload

let payload_of_string payload_str =
  let payload = RBase64.url_decode payload_str in
  RResult.map Yojson.Safe.from_string payload

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

let to_string t =
  let payload = RBase64.url_encode_string t.raw_payload in
  Printf.sprintf "%s.%s.%s" t.raw_header payload t.signature

let of_string token =
  String.split_on_char '.' token |> function
  | [ header_str; payload_str; signature ] ->
      let header = Header.of_string header_str in
      let payload = payload_of_string payload_str in
      RResult.both header payload
      |> RResult.flat_map (fun (header, payload) ->
             Ok
               {
                 header;
                 raw_header = header_str;
                 payload;
                 raw_payload = RBase64.url_decode payload_str |> RResult.get_exn;
                 (* The string is already decoded so this is fine but redundant *)
                 signature;
               })
  | _ -> Error (`Msg "token didn't include header, payload or signature")

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

let check_exp t =
  let module Json = Yojson.Safe.Util in
  match Json.member "exp" t.payload |> Json.to_int_option with
  | Some exp when exp > int_of_float (Unix.time ()) -> Ok t
  | Some _exp -> Error `Expired
  | None -> Ok t

let validate (type a) ~(jwk : a Jwk.t) (t : t) : (t, 'error) result =
  Jws.validate ~jwk (to_jws t) |> RResult.map of_jws

let sign ~(header : Header.t) ~payload (jwk : Jwk.priv Jwk.t) =
  let payload =
    try Ok (Yojson.Safe.to_string payload)
    with _ -> Error (`Msg "Can't serialize payload")
  in
  match payload with
  | Ok payload -> Jws.sign ~header ~payload jwk |> RResult.map of_jws
  | Error e -> Error e
