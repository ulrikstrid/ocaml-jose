open Utils;

type algorithm = [ | `RSA | `Unknown];
type typ = [ | `JWT | `Unknown];

type t = {
  alg: algorithm,
  typ,
  kid: string,
};

let make_header = (jwk: Jwk.Pub.t) => {alg: `RSA, typ: `JWT, kid: jwk.kid};

let string_to_header = header_str => {
  let to_alg = alg => {
    switch (alg) {
    | "RS256" => `RSA
    | _ => `Unknown
    };
  };

  let to_typ = typ =>
    switch (typ) {
    | Some("JWT") => `JWT
    | _ => `Unknown
    };

  RBase64.base64_url_decode(header_str)
  |> RResult.map(decoded_header => {
       Yojson.Safe.from_string(decoded_header)
       |> (
         json => {
           alg:
             Yojson.Safe.Util.member("alg", json)
             |> Yojson.Safe.Util.to_string
             |> to_alg,
           typ:
             Yojson.Safe.Util.member("typ", json)
             |> Yojson.Safe.Util.to_string_option
             |> to_typ,
           kid:
             Yojson.Safe.Util.member("kid", json)
             |> Yojson.Safe.Util.to_string,
         }
       )
     });
};

let header_to_string = header => {
  let alg =
    switch (header.alg) {
    | `RSA => "RS256"
    | _ => "Unknown"
    };

  let typ =
    switch (header.typ) {
    | `JWT => "JWT"
    | _ => "Unknown"
    };

  `Assoc([
    ("typ", `String(typ)),
    ("alg", `String(alg)),
    ("kid", `String(header.kid)),
  ])
  |> Yojson.Safe.to_string
  |> RBase64.base64_url_encode;
};
