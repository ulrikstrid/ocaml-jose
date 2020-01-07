open Utils;

type signature = string;

type t = {
  header: Header.t,
  payload: string,
  signature,
};

let verify_internal = (~pub_key, t) => {
  Header.to_string(t.header)
  |> RResult.flat_map(header_str => {
       let input_str = header_str ++ "." ++ t.payload;

       t.signature
       |> RBase64.base64_url_decode
       |> RResult.map(Cstruct.of_string)
       |> RResult.map(s =>
            switch (Nocrypto.Rsa.PKCS1.sig_decode(~key=pub_key, s)) {
            | None => Error(`Msg("Could not decode signature"))
            | Some(message) =>
              let token_hash =
                input_str |> Cstruct.of_string |> Nocrypto.Hash.SHA256.digest;
              Ok(Cstruct.equal(message, token_hash));
            }
          );
     });
};

let validate = (~jwks: Jwks.t, t) => {
  let header = t.header;

  (
    switch (header.alg) {
    | `RS256 => Ok(header.alg)
    | _ => Error(`Msg("alg must be RS256"))
    }
  )
  |> RResult.flat_map(_ =>
       RList.find_opt(
         (jwk: Jwk.Pub.t) =>
           jwk.kid == CCOpt.get_or(~default="", header.kid),
         jwks.keys,
       )
       |> (
         fun
         | Some(jwk) => Ok(jwk)
         | None => Error(`Msg("Did not find key with correct kid"))
       )
     )
  |> RResult.flat_map(Jwk.Pub.to_pub)
  |> RResult.flat_map(pub_key => verify_internal(~pub_key, t))
  |> RResult.map(_ => t);
};

let sign = (~header, ~payload, key) => {
  Header.to_string(header)
  |> RResult.flat_map(header_str => {
       let input_str = header_str ++ "." ++ payload;

       `Message(Cstruct.of_string(input_str))
       |> Nocrypto.Rsa.PKCS1.sign(~hash=`SHA256, ~key)
       |> Cstruct.to_string
       |> RBase64.base64_url_encode
       |> RResult.map(sign => (header, payload, sign));
     })
  |> RResult.map(((header, payload, signature)) => {
       {header, payload, signature}
     });
};
