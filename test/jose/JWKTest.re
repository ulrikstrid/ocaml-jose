open TestFramework;

describe("JWK.Pub", ({test}) => {
  test("Creates a correct JWK from pem", ({expect}) => {
    Jose.Jwk.Pub.rsa_of_pub_pem(Fixtures.rsa_test_pub)
    |> (
      r => {
        open Jose.Jwk.Pub;
        expect.result(r).toBeOk();

        CCResult.get_exn(r)
        |> (
          jwk => {
            expect.string(jwk.kty |> Jose.Jwa.kty_to_string).toEqual(
              Fixtures.private_jwk.kty |> Jose.Jwa.kty_to_string,
            );
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
    Jose.Jwk.Pub.rsa_of_pub_pem(Fixtures.rsa_test_pub)
    |> CCResult.flat_map(Jose.Jwk.Pub.rsa_to_pub_pem)
    |> CCResult.get_exn
    |> (
      pub_cert => {
        expect.string(pub_cert).toEqual(Fixtures.rsa_test_pub);
      }
    )
  });

  test("of_json", ({expect}) => {
    let jwk = Jose.Jwk.Pub.of_string(Fixtures.public_jwk_string);

    expect.result(jwk).toBeOk();

    CCResult.get_exn(jwk)
    |> (
      (RSA(jwk)) => {
        expect.string(jwk.kty |> Jose.Jwa.kty_to_string).toEqual(
          Fixtures.private_jwk.kty |> Jose.Jwa.kty_to_string,
        );
        expect.string(jwk.e).toEqual(Fixtures.private_jwk.e);
        expect.string(jwk.n).toEqual(Fixtures.private_jwk.n);
        // TODO: Figure if we want to do the same as Panva with kid
        expect.string(jwk.kid).toEqual(
          "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik",
        );
      }
    );
  });
  /*
   test("oct_of_string", ({expect}) => {
     let oct: Jose.Jwk.Pub.oct =
       Jose.Jwk.Pub.oct_of_string(
         "Thus from my lips, by yours, my sin is purged.",
       );

     expect.string(oct.k).toEqual(
       "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
     );
   });
   */
});

describe("JWK.Priv", ({test}) => {
  test("Creates a correct JWK from pem", ({expect}) => {
    Jose.Jwk.Priv.of_priv_pem(Fixtures.rsa_test_priv)
    |> (
      r => {
        open Jose.Jwk.Priv;
        expect.result(r).toBeOk();

        CCResult.get_exn(r)
        |> (
          jwk => {
            expect.string(jwk.kty |> Jose.Jwa.kty_to_string).toEqual(
              Fixtures.private_jwk.kty |> Jose.Jwa.kty_to_string,
            );
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
