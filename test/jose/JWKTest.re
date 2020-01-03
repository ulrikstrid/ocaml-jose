open TestFramework;

describe("JWK.Pub", ({test}) => {
  test("Creates a correct jwt from pem", ({expect}) => {
    Jose.Jwk.Pub.of_pub_pem(Fixtures.rsa_test_pub)
    |> (
      r => {
        open Jose.Jwk.Pub;
        expect.result(r).toBeOk();

        CCResult.get_exn(r)
        |> (
          jwk => {
            expect.string(jwk.kty).toEqual(Fixtures.private_jwk.kty);
            expect.string(jwk.e).toEqual(Fixtures.private_jwk.e);
            expect.string(jwk.n).toEqual(Fixtures.private_jwk.n);
            // TODO: Figure if we want to do the same as Panva with kid
            expect.string(jwk.kid).toEqual("Yivu3QTFD7-Dkkd6dlKdhOCpfWg=");
          }
        );
      }
    )
  });

  test("Roundtrip", ({expect}) => {
    Jose.Jwk.Pub.of_pub_pem(Fixtures.rsa_test_pub)
    |> CCResult.flat_map(Jose.Jwk.Pub.to_pub_pem)
    |> CCResult.get_exn
    |> (
      pub_cert => {
        expect.string(pub_cert).toEqual(Fixtures.rsa_test_pub);
      }
    )
  });

  test("of_json", ({expect}) => {
    Jose.Jwk.Pub.of_string(Fixtures.public_jwk_string)
    |> CCResult.get_exn
    |> (
      jwk => {
        expect.string(jwk.kty).toEqual(Fixtures.private_jwk.kty);
        expect.string(jwk.e).toEqual(Fixtures.private_jwk.e);
        expect.string(jwk.n).toEqual(Fixtures.private_jwk.n);
        // TODO: Figure if we want to do the same as Panva with kid
        expect.string(jwk.kid).toEqual(
          "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik",
        );
      }
    )
  });
});

describe("JWK.Priv", ({test}) => {
  test("Creates a correct jwt from pem", ({expect}) => {
    Jose.Jwk.Priv.of_priv_pem(Fixtures.rsa_test_priv)
    |> (
      r => {
        open Jose.Jwk.Priv;
        expect.result(r).toBeOk();

        CCResult.get_exn(r)
        |> (
          jwk => {
            expect.string(jwk.kty).toEqual(Fixtures.private_jwk.kty);
            expect.string(jwk.e).toEqual(Fixtures.private_jwk.e);
            expect.string(jwk.n).toEqual(Fixtures.private_jwk.n);
            expect.string(jwk.d).toEqual(Fixtures.private_jwk.d);
            expect.string(jwk.p).toEqual(Fixtures.private_jwk.p);
            expect.string(jwk.q).toEqual(Fixtures.private_jwk.q);
            expect.string(jwk.dp).toEqual(Fixtures.private_jwk.dp);
            expect.string(jwk.dq).toEqual(Fixtures.private_jwk.dq);
            expect.string(jwk.qi).toEqual(Fixtures.private_jwk.qi);
          }
        );
      }
    )
  });

  test("Roundtrip", ({expect}) => {
    Jose.Jwk.Priv.of_priv_pem(Fixtures.rsa_test_priv)
    |> CCResult.flat_map(Jose.Jwk.Priv.to_priv_pem)
    |> CCResult.get_exn
    |> (
      pub_cert => {
        expect.string(pub_cert).toEqual(Fixtures.rsa_test_priv);
      }
    )
  });

  test("Creates well formed rsa", ({expect}) => {
    Jose.Jwk.Priv.to_priv(Fixtures.private_jwk)
    |> CCResult.get_exn
    |> (rsa => Nocrypto.Rsa.well_formed(~e=rsa.e, ~p=rsa.p, ~q=rsa.q))
    |> (a => expect.bool(a).toBeTrue())
  });
});
