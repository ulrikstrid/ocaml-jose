open Utils;

type payload = Yojson.Safe.t;
type claim = (string, Yojson.Safe.t);

let empty_payload = `Assoc([]);

let payload_to_string = payload => {
  payload |> Yojson.Safe.to_string |> RBase64.base64_url_encode;
};

let payload_of_string = payload_str => {
  RBase64.base64_url_decode(payload_str)
  |> RResult.map(Yojson.Safe.from_string);
};

type t = {
  header: Header.t,
  payload,
  signature: Jws.signature,
};

let add_claim =
    (claim_name: string, claim_value: Yojson.Safe.t, payload: payload) =>
  `Assoc([
    (claim_name, claim_value),
    ...Yojson.Safe.Util.to_assoc(payload),
  ]);

let to_string = t => {
  let header_str = Header.header_to_string(t.header);
  let payload_str = payload_to_string(t.payload);

  RResult.both(header_str, payload_str)
  |> RResult.map(((header_str, payload_str)) =>
       header_str ++ "." ++ payload_str ++ "." ++ t.signature
     );
};

let of_string = token => {
  String.split_on_char('.', token)
  |> (
    fun
    | [header_str, payload_str, signature] => {
        let header = Header.string_to_header(header_str);
        let payload = payload_of_string(payload_str);
        RResult.both(header, payload)
        |> RResult.flat_map(((header, payload)) =>
             Ok({header, payload, signature})
           );
      }
    | _ => Error(`Msg("token didn't include header, payload or signature"))
  );
};

let to_jws = t =>
  payload_to_string(t.payload)
  |> RResult.map((payload: string) =>
       Jws.{header: t.header, signature: t.signature, payload}
     );

let of_jws = (jws: Jws.t) =>
  payload_of_string(jws.payload)
  |> RResult.map(payload =>
       {header: jws.header, signature: jws.signature, payload}
     );

let check_exp = t => {
  module Json = Yojson.Safe.Util;
  switch (Json.member("exp", t.payload) |> Json.to_int_option) {
  | Some(exp) when exp > int_of_float(Unix.time()) => Ok(t)
  | Some(_exp) => Error(`Msg("Token expired"))
  | None => Ok(t)
  };
};

let validate = (~jwks, t) => {
  check_exp(t)
  |> RResult.flat_map(to_jws)
  |> RResult.flat_map(Jws.validate(~jwks))
  |> RResult.flat_map(of_jws);
};

let sign = (~header, ~payload, key) =>
  payload_to_string(payload)
  |> RResult.flat_map(payload => Jws.sign(~header, ~payload, key))
  |> RResult.flat_map(of_jws);
