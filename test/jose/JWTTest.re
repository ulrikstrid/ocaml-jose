open TestFramework;
open Jose;

let {describe} =
  describeConfig
  |> withLifecycle(testLifecycle =>
       testLifecycle |> beforeAll(() => Nocrypto_entropy_unix.initialize())
     )
  |> build;

describe("JWT", ({test}) => {
  test("Can validate a RSA256 JWT", ({expect}) => {
    let rsa =
      Jwk.Pub.rsa_of_pub_pem(Fixtures.rsa_test_pub) |> CCResult.get_exn;
    let jwks =
      Jwks.{
        keys: [
          RSA({...rsa, kid: "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik"}),
        ],
      };

    Jwt.of_string(Fixtures.external_jwt_string)
    |> CCResult.flat_map(Jwt.validate(~jwks))
    |> (jwt_result => expect.result(jwt_result).toBeOk());
  });

  test("Can validate a HS256 JWT", ({expect}) => {
    let jwks =
      Jwks.{
        keys: [
          OCT(
            {
              Fixtures.oct_jwk;
            },
          ),
        ],
      };

    Jwt.of_string(Fixtures.oct_jwt_string)
    |> CCResult.flat_map(Jwt.validate(~jwks))
    |> (jwt_result => expect.result(jwt_result).toBeOk());
  });

  test("Can create a JWT", ({expect}) => {
    let header = Header.make_header(~typ="JWT", Fixtures.public_jwk);
    expect.string(Header.to_json(header) |> Yojson.Safe.to_string).toEqual(
      {|{"typ":"JWT","alg":"RS256","kid":"0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik"}|},
    );
    expect.string(
      Header.to_json(header)
      |> Yojson.Safe.Util.member("alg")
      |> Yojson.Safe.Util.to_string,
    ).
      toEqual(
      "RS256",
    );
    let payload =
      Jwt.empty_payload |> Jwt.add_claim("sub", `String("tester"));
    let jwt =
      Jwt.sign(
        ~header,
        ~payload,
        Fixtures.private_jwk |> Jwk.Priv.to_priv |> CCResult.get_exn,
      );

    expect.string(
      jwt |> CCResult.flat_map(Jwt.to_string) |> CCResult.get_exn,
    ).
      toEqual(
      Fixtures.external_jwt_string,
    );
  });

  test("Can validate my own JWT", ({expect}) => {
    let header = Header.make_header(Fixtures.public_jwk);
    let payload =
      Jwt.empty_payload |> Jwt.add_claim("sub", `String("tester"));
    let jwt =
      Jwt.sign(
        ~header,
        ~payload,
        Fixtures.private_jwk |> Jwk.Priv.to_priv |> CCResult.get_exn,
      )
      |> CCResult.get_exn;

    expect.result(
      Jwt.validate(~jwks=Jwks.{keys: [Fixtures.public_jwk]}, jwt),
    ).
      toBeOk();
  });
});
