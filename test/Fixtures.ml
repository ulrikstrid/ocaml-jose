let rsa_test_priv =
  {|-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDo+jbfEmKkTIF9
XCsGrrysgPw0hKC/dGQtG3DPpiZ10i/O3gpHuRBtF6RO+BntgOcIMq2v6XBuK9fr
+1H/2SWnwEoK2Tuta6i42Fo4Dma1/CnzTO192qobLbnQoyrI7V8PuYox9B9HtYx7
5bXKA04bZiVLOEY4MakTYVLPp1weU5NrkAkcS+ivXvbcSS8PwWOqiUlM62W9tSD0
P0dZgdO0w62KIpJP2tEVpwHsD6mnPOfyF6IH+pzlRDiBvDWLumpwrPCrNoRofAGu
/cINnbzDBk3HK2v3u7eEZpEfY1LAHo6F/uaiPT59DS5j1RlxoUqve8aoUf82ijmR
WbnMW10lAgMBAAECggEAELnN8KvgOw1nCnnweNVYpEXKVXbkF3qiqn5a1f2Gq1TA
q+hS8p09qadV23mCWwOzEmqY/5URxkcNhFqRo32Sb32lkyvPVf7xqPuXVojqJMyK
snXmYu+s4LCis3DTZINuHLHkUvvEtyA4iriOGYetNthZexH6MJSYH9UP3eqU+XRB
f3lw3oU+ZWJcnJiEvJa2H4haf70C0mFdTyKQQkops4QkgBEVIVtaVHXPgFnH1eh9
uUSWlTiWqauWqe1h5jaEZbFAWPyanYAizLbGeQyOYf1N+0E4OsoRIiTQp1rRGfxU
YO2mQelv2j15IXyQ8fZOCjvGEwiTQ6qn8g+UN4aFzQKBgQD7aodkMYS8p+a5N52d
VhC03tZMcRqYKEutsTwDG5FdjoXou/DMJHfR7owb71gBpSZtfmA15BuFgHEvXc+O
8ska2KDcBUIfOO3PvsD3ap41zwCMZ2DMyngSlycgknHdzsR4CiB7/D/zmkLBWYNO
vZVRKxBYgEHcfxkiWVrPKj0QGwKBgQDtOZ+rEUtWwu0PSb5giF7Bt5iK6y+cDI9k
G8o5JncugjP5WrRLH8VjKzuL7fT3aNnUu02oOCg5mpFmGWu1QXuWpGrcbfgd5xg3
qN/ZSFljqmwoLdT83uW8h4Dn+MI0NJRXYZZQHr4GujzGp/Zb8yYlV7RgrFpxmSO9
kO2LaOSbvwKBgQCDaSARZ6yYqy32m7I/fa/Hyj26wNeEtnMv+1aBzVQC0a7+gdWP
7nPOf+At7cFTQs4+JvME2BDmi8cdWexWLGKfLKGPvxPbm/b5Qhw8djbxqxv/Rz2a
bS2rkeP6q3Dm3d9lWu21wJhwrK29wBrY+lDklxy5FXjXVnt9r7S+WbaHBwKBgBCV
5MnrDZ9lRXm6KCtLnYRht7KOuudoIWZYYw0X2WFRDR0z8EMIV56VWTZxTp01oXU0
GzvVoUpVujCvOk6T43YmzKnYrm44yAKsNepVGprTQXiVq7x6QQmrV6HgTIOl4XEy
i3XSkGqb/r/M4naPS2108lGH+1LR6CPKzDDhBoq1AoGBAIXvuhHZuTpW+S7XosUo
3OLEi3Xo3ZS4NHViKhFMQTQgKtoO3K4yWgBTh3qu2p8EhavZpZQWDu2LGISjPpW1
vKYFpE2KyahSJmfZ21UzsrwoaMuuy31kggReTt1yEJm/CnTDGihgCLqKAi389GG6
EQBaMSFXOODiel+5MdQcj41b
-----END PRIVATE KEY-----
|}

let private_jwk : Jose.Jwk.Priv.rsa =
  {
    e = "AQAB";
    n =
      "6Po23xJipEyBfVwrBq68rID8NISgv3RkLRtwz6YmddIvzt4KR7kQbRekTvgZ7YDnCDKtr-lwbivX6_tR_9klp8BKCtk7rWuouNhaOA5mtfwp80ztfdqqGy250KMqyO1fD7mKMfQfR7WMe-W1ygNOG2YlSzhGODGpE2FSz6dcHlOTa5AJHEvor1723EkvD8FjqolJTOtlvbUg9D9HWYHTtMOtiiKST9rRFacB7A-ppzzn8heiB_qc5UQ4gbw1i7pqcKzwqzaEaHwBrv3CDZ28wwZNxytr97u3hGaRH2NSwB6Ohf7moj0-fQ0uY9UZcaFKr3vGqFH_Noo5kVm5zFtdJQ";
    d =
      "ELnN8KvgOw1nCnnweNVYpEXKVXbkF3qiqn5a1f2Gq1TAq-hS8p09qadV23mCWwOzEmqY_5URxkcNhFqRo32Sb32lkyvPVf7xqPuXVojqJMyKsnXmYu-s4LCis3DTZINuHLHkUvvEtyA4iriOGYetNthZexH6MJSYH9UP3eqU-XRBf3lw3oU-ZWJcnJiEvJa2H4haf70C0mFdTyKQQkops4QkgBEVIVtaVHXPgFnH1eh9uUSWlTiWqauWqe1h5jaEZbFAWPyanYAizLbGeQyOYf1N-0E4OsoRIiTQp1rRGfxUYO2mQelv2j15IXyQ8fZOCjvGEwiTQ6qn8g-UN4aFzQ";
    p =
      "-2qHZDGEvKfmuTednVYQtN7WTHEamChLrbE8AxuRXY6F6LvwzCR30e6MG-9YAaUmbX5gNeQbhYBxL13PjvLJGtig3AVCHzjtz77A92qeNc8AjGdgzMp4EpcnIJJx3c7EeAoge_w_85pCwVmDTr2VUSsQWIBB3H8ZIllazyo9EBs";
    q =
      "7TmfqxFLVsLtD0m-YIhewbeYiusvnAyPZBvKOSZ3LoIz-Vq0Sx_FYys7i-3092jZ1LtNqDgoOZqRZhlrtUF7lqRq3G34HecYN6jf2UhZY6psKC3U_N7lvIeA5_jCNDSUV2GWUB6-Bro8xqf2W_MmJVe0YKxacZkjvZDti2jkm78";
    dp =
      "g2kgEWesmKst9puyP32vx8o9usDXhLZzL_tWgc1UAtGu_oHVj-5zzn_gLe3BU0LOPibzBNgQ5ovHHVnsVixinyyhj78T25v2-UIcPHY28asb_0c9mm0tq5Hj-qtw5t3fZVrttcCYcKytvcAa2PpQ5JccuRV411Z7fa-0vlm2hwc";
    dq =
      "EJXkyesNn2VFebooK0udhGG3so6652ghZlhjDRfZYVENHTPwQwhXnpVZNnFOnTWhdTQbO9WhSlW6MK86TpPjdibMqdiubjjIAqw16lUamtNBeJWrvHpBCatXoeBMg6XhcTKLddKQapv-v8zido9LbXTyUYf7UtHoI8rMMOEGirU";
    qi =
      "he-6Edm5Olb5LteixSjc4sSLdejdlLg0dWIqEUxBNCAq2g7crjJaAFOHeq7anwSFq9mllBYO7YsYhKM-lbW8pgWkTYrJqFImZ9nbVTOyvChoy67LfWSCBF5O3XIQmb8KdMMaKGAIuooCLfz0YboRAFoxIVc44OJ6X7kx1ByPjVs";
    kty = `RSA;
    kid = "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik";
    alg = `RS256;
  }

let private_jwk_string =
  {|{"alg": "RS256",
"e": "AQAB",
"n": "6Po23xJipEyBfVwrBq68rID8NISgv3RkLRtwz6YmddIvzt4KR7kQbRekTvgZ7YDnCDKtr-lwbivX6_tR_9klp8BKCtk7rWuouNhaOA5mtfwp80ztfdqqGy250KMqyO1fD7mKMfQfR7WMe-W1ygNOG2YlSzhGODGpE2FSz6dcHlOTa5AJHEvor1723EkvD8FjqolJTOtlvbUg9D9HWYHTtMOtiiKST9rRFacB7A-ppzzn8heiB_qc5UQ4gbw1i7pqcKzwqzaEaHwBrv3CDZ28wwZNxytr97u3hGaRH2NSwB6Ohf7moj0-fQ0uY9UZcaFKr3vGqFH_Noo5kVm5zFtdJQ",
"d": "ELnN8KvgOw1nCnnweNVYpEXKVXbkF3qiqn5a1f2Gq1TAq-hS8p09qadV23mCWwOzEmqY_5URxkcNhFqRo32Sb32lkyvPVf7xqPuXVojqJMyKsnXmYu-s4LCis3DTZINuHLHkUvvEtyA4iriOGYetNthZexH6MJSYH9UP3eqU-XRBf3lw3oU-ZWJcnJiEvJa2H4haf70C0mFdTyKQQkops4QkgBEVIVtaVHXPgFnH1eh9uUSWlTiWqauWqe1h5jaEZbFAWPyanYAizLbGeQyOYf1N-0E4OsoRIiTQp1rRGfxUYO2mQelv2j15IXyQ8fZOCjvGEwiTQ6qn8g-UN4aFzQ",
"p": "-2qHZDGEvKfmuTednVYQtN7WTHEamChLrbE8AxuRXY6F6LvwzCR30e6MG-9YAaUmbX5gNeQbhYBxL13PjvLJGtig3AVCHzjtz77A92qeNc8AjGdgzMp4EpcnIJJx3c7EeAoge_w_85pCwVmDTr2VUSsQWIBB3H8ZIllazyo9EBs",
"q": "7TmfqxFLVsLtD0m-YIhewbeYiusvnAyPZBvKOSZ3LoIz-Vq0Sx_FYys7i-3092jZ1LtNqDgoOZqRZhlrtUF7lqRq3G34HecYN6jf2UhZY6psKC3U_N7lvIeA5_jCNDSUV2GWUB6-Bro8xqf2W_MmJVe0YKxacZkjvZDti2jkm78",
"dp": "g2kgEWesmKst9puyP32vx8o9usDXhLZzL_tWgc1UAtGu_oHVj-5zzn_gLe3BU0LOPibzBNgQ5ovHHVnsVixinyyhj78T25v2-UIcPHY28asb_0c9mm0tq5Hj-qtw5t3fZVrttcCYcKytvcAa2PpQ5JccuRV411Z7fa-0vlm2hwc",
"dq": "EJXkyesNn2VFebooK0udhGG3so6652ghZlhjDRfZYVENHTPwQwhXnpVZNnFOnTWhdTQbO9WhSlW6MK86TpPjdibMqdiubjjIAqw16lUamtNBeJWrvHpBCatXoeBMg6XhcTKLddKQapv-v8zido9LbXTyUYf7UtHoI8rMMOEGirU",
"qi": "he-6Edm5Olb5LteixSjc4sSLdejdlLg0dWIqEUxBNCAq2g7crjJaAFOHeq7anwSFq9mllBYO7YsYhKM-lbW8pgWkTYrJqFImZ9nbVTOyvChoy67LfWSCBF5O3XIQmb8KdMMaKGAIuooCLfz0YboRAFoxIVc44OJ6X7kx1ByPjVs",
"kty": "RSA",
"use": "sign",
"kid": "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik"}|}

let rsa_test_pub =
  {|-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6Po23xJipEyBfVwrBq68
rID8NISgv3RkLRtwz6YmddIvzt4KR7kQbRekTvgZ7YDnCDKtr+lwbivX6/tR/9kl
p8BKCtk7rWuouNhaOA5mtfwp80ztfdqqGy250KMqyO1fD7mKMfQfR7WMe+W1ygNO
G2YlSzhGODGpE2FSz6dcHlOTa5AJHEvor1723EkvD8FjqolJTOtlvbUg9D9HWYHT
tMOtiiKST9rRFacB7A+ppzzn8heiB/qc5UQ4gbw1i7pqcKzwqzaEaHwBrv3CDZ28
wwZNxytr97u3hGaRH2NSwB6Ohf7moj0+fQ0uY9UZcaFKr3vGqFH/Noo5kVm5zFtd
JQIDAQAB
-----END PUBLIC KEY-----
|}

let public_jwk : Jose.Jwk.Pub.rsa =
  {
    alg = `RS256;
    e = "AQAB";
    n =
      "6Po23xJipEyBfVwrBq68rID8NISgv3RkLRtwz6YmddIvzt4KR7kQbRekTvgZ7YDnCDKtr-lwbivX6_tR_9klp8BKCtk7rWuouNhaOA5mtfwp80ztfdqqGy250KMqyO1fD7mKMfQfR7WMe-W1ygNOG2YlSzhGODGpE2FSz6dcHlOTa5AJHEvor1723EkvD8FjqolJTOtlvbUg9D9HWYHTtMOtiiKST9rRFacB7A-ppzzn8heiB_qc5UQ4gbw1i7pqcKzwqzaEaHwBrv3CDZ28wwZNxytr97u3hGaRH2NSwB6Ohf7moj0-fQ0uY9UZcaFKr3vGqFH_Noo5kVm5zFtdJQ";
    kty = `RSA;
    kid = "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik";
    use = (Some "sign" [@explicit_arity]);
    x5t = None;
  }

let public_jwk_string =
  {|{"alg": "RS256",
"e": "AQAB",
"n": "6Po23xJipEyBfVwrBq68rID8NISgv3RkLRtwz6YmddIvzt4KR7kQbRekTvgZ7YDnCDKtr-lwbivX6_tR_9klp8BKCtk7rWuouNhaOA5mtfwp80ztfdqqGy250KMqyO1fD7mKMfQfR7WMe-W1ygNOG2YlSzhGODGpE2FSz6dcHlOTa5AJHEvor1723EkvD8FjqolJTOtlvbUg9D9HWYHTtMOtiiKST9rRFacB7A-ppzzn8heiB_qc5UQ4gbw1i7pqcKzwqzaEaHwBrv3CDZ28wwZNxytr97u3hGaRH2NSwB6Ohf7moj0-fQ0uY9UZcaFKr3vGqFH_Noo5kVm5zFtdJQ",
"kty": "RSA",
"kid": "0IRFN_RUHUQcXcdp_7PLBxoG_9b6bHrvGH0p8qRotik",
"use": "sign",
"x5t":"LiE8S21-GUjC1x4er0S9g76rYbQ"}|}

let external_jwt_string =
  {|eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBJUkZOX1JVSFVRY1hjZHBfN1BMQnhvR185YjZiSHJ2R0gwcDhxUm90aWsifQ.eyJzdWIiOiJ0ZXN0ZXIifQ.Jl9BJyYkLW5sHXpmxM4VNA9IEVFxTKkqWw4TkXBfj02xuLGY4cYKz_IlLEBeUN-mHGEJ8hiJMhaybBI2OM2FBahK-csLgjVuPBAznsGVsW6wAWZR47AeoBLr8uh09IYbEpHvqA_aIBdM5pvgM9_t3VtC9L50944HmTcmOkGR9BzaINk33ubYIgkXfClVNzTXc5PiD6haJqhPRb6XS5UZQOHIhyTtJ3gl1NX0LEBRH5ZsgEe_5L8ZNSoAcBFnuS-XMTy7Z4PacBtZG9Y8NHh90K45WTeS7pQw6GR-AQsrrkW-xkDMF_79qJkvVPU6UneaJjMtQctki1RDRZWF32I5mQ|}

let oct_jwt_string =
  {|eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Iko0eFFoN3otRWFKSTdQeTFQNHJGZjJTMHJwcFAybTR5S3JaVzRYNFlmdWsifQ.eyJzdWIiOiJ0ZXN0ZXIifQ.VSzni5ed3P9_vimTe9Weu56vTlMsSGHZY-WjnUo7S0A|}

let oct_jwk_pub : Jose.Jwk.Pub.oct =
  {
    k = "MDZjM2JkNWMtMGY5Ny00YjNlLWJmMjAtZWIyOWFlOTM2M2Rl";
    kty = `oct;
    use = Some "sig";
    kid = "J4xQh7z-EaJI7Py1P4rFf2S0rppP2m4yKrZW4X4Yfuk";
    alg = `HS256;
  }

let oct_jwk_priv : Jose.Jwk.Priv.oct =
  {
    k = "MDZjM2JkNWMtMGY5Ny00YjNlLWJmMjAtZWIyOWFlOTM2M2Rl";
    kty = `oct;
    use = Some "sig";
    kid = "J4xQh7z-EaJI7Py1P4rFf2S0rppP2m4yKrZW4X4Yfuk";
    alg = `HS256;
  }

let oct_jwk_string =
  {|{"alg":"HS256","kty":"oct","k":"MDZjM2JkNWMtMGY5Ny00YjNlLWJmMjAtZWIyOWFlOTM2M2Rl","kid":"J4xQh7z-EaJI7Py1P4rFf2S0rppP2m4yKrZW4X4Yfuk"}|}

let jwks_string_from_oidc_validation =
  {|{"keys": [{"kty": "RSA", "use": "enc", "kid": "ip69fvSevxvcFHy8FSHY7zUOULQ_ceCmkn4U1nhPS3k", "n": "vsOB2NSSR1HbK3MGelDc6mKJN5QbnxJ_VBFPd3S47TbFAhAiescxcG27KHvZDsapauqLC1RwL27XLbKO5u8wY32u3JOFEUtGSObEbUYylhB-eTqpqotqa8Du5k39XyOB6QU5cmzDRyLl8PUWri5KUgmPQaFa-m556yj5ydGatacxWio5fQe55Mx3guzHQShcmOZcFzKkw23B7Jbx-15qL2CEZ2E5iweNvRTeDfp1P7Q1pn4Ir9ANYEJSpCktoK4B6LEsfPzohUj7urVIHRpgUjaTUGFkbHGjcE3EvbKO70Ha_YFqslettb88nkbkQRVZ-NPaSL6ewqaXYhYb2Qt80w", "e": "AQAB"}, {"kty": "RSA", "use": "sig", "kid": "_Zn6QEz3Dn6RnW7hopaAc46VFepZQkLyFO2pNt3Us4Y", "n": "y9tjZ4zSfvwfFulZFrLOpq1zzM4a6SrWLBxB3KdM78FoVsIq-HiqByW1Kt4kkUDEtl02OB-C3ZU7Ku3UAWbnwZlkAybCRgOmnnp3EynIT-skUcXWrx93MLBPSMaGG4WRIGadTaMck6SlHwN6Fyw5n8KGgovaI47V1vdGVh6_tkvjXq3eppYd-u2-7S1PU2ccDVFtWyunqGTuYUJzBrToz2ms4ffNUZ2oc5ZWNZbo40M2OsRPAJqCNSr0XwG76kCi7ACQh1OR_6k2YUfbME8zeOvibTEaAUpI1tmcNEGf1ZyYI_ONUI0mv4xAjUkFgxJ2hGaEkgJ1-6Ag_pFOZfa3cw", "e": "AQAB"}, {"kty": "EC", "use": "sig", "kid": "mk3JmWss9URzc7SC9wpGRLto-56kg_YjUhS18JCm6mM", "crv": "P-256", "x": "dAZGr9AkcVx0Sf0f3OsbgXx9fxBZ5uz0uTx2oVbDaSs", "y": "8uZL-bviipURsp4ug3-nbU7UhdfMTgBEEW-bL7Gx180"}, {"kty": "EC", "use": "enc", "kid": "OXMZf-IGfQ5UEQG1zANT6NBS_cR8Zqzil01kH_mUquA", "crv": "P-256", "x": "OXVW1Z-nBZFfJfoavnaEamnx_Z5oSBWDX2WuBbXVd-o", "y": "yXxr5Tx0h5jiZM7rYbZVo9Qoz4hIcLwSNvQioSIFYQ8"}]}|}
