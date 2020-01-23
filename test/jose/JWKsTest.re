open TestFramework;

describe("JWKs", ({test}) => {
  let trimed_json =
    Fixtures.public_jwk_string
    |> CCString.replace(~sub=" ", ~by="")
    |> CCString.replace(~sub="\n", ~by="");
  let expected_jwks_string = {|{"keys":[|} ++ trimed_json ++ "]}";

  test("Creates a correct JSON from a JWKs", ({expect}) => {
    let jwks_string =
      Jose.Jwks.to_string({keys: [Jose.Jwk.Pub.RSA(Fixtures.public_jwk)]});

    expect.string(jwks_string).toEqual(expected_jwks_string);
  });

  test("Creates a correct JWKs from JSON", ({expect}) => {
    let jwks = Jose.Jwks.of_string(expected_jwks_string);

    let jwk = Jose.Jwks.find_key(jwks, Fixtures.public_jwk.kid);
    expect.option(jwk).toBeSome();

    let jwk = CCOpt.get_exn(jwk);

    expect.string(jwk |> Jose.Jwk.Pub.get_kid).toEqual(
      Fixtures.public_jwk.kid,
    );
  });
});
