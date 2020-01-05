open TestFramework;
open Jose;

let {describe} =
  describeConfig
  |> withLifecycle(testLifecycle =>
       testLifecycle |> beforeAll(() => Nocrypto_entropy_unix.initialize())
     )
  |> build;

describe("JWT", ({test}) => {
  let jwk = Jwk.Pub.of_pub_pem(Fixtures.rsa_test_pub) |> CCResult.get_exn;

  test("Can validate a JWT", ({expect}) => {
    let jwt_result =
      Jwt.from_string(Fixtures.external_jwt_string)
      |> CCResult.get_exn
      |> Jwt.verify(
           ~jwks=[
             {...jwk, kid: "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik"},
           ],
         );

    expect.result(jwt_result).toBeOk();
  });

  test("Can create a JWT", ({expect}) => {
    let header = Jwt.make_header(Fixtures.public_jwk);
    let payload =
      Jwt.empty_payload |> Jwt.add_claim("sub", `String("tester"));
    let jwt =
      Jwt.sign(
        header,
        Fixtures.private_jwk |> Jwk.Priv.to_priv |> CCResult.get_exn,
        payload,
      );

    expect.string(jwt |> CCResult.get_exn |> Jwt.to_string).toEqual(
      Fixtures.external_jwt_string,
    );
  });

  test("Can validate my own JWT", ({expect}) => {
    let header = Jwt.make_header(Fixtures.public_jwk);
    let payload =
      Jwt.empty_payload |> Jwt.add_claim("sub", `String("tester"));
    let jwt =
      Jwt.sign(
        header,
        Fixtures.private_jwk |> Jwk.Priv.to_priv |> CCResult.get_exn,
        payload,
      )
      |> CCResult.get_exn;

    expect.result(Jwt.verify(~jwks=[Fixtures.public_jwk], jwt)).toBeOk();
  });
});
