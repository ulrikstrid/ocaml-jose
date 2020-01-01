open TestFramework;
open Http;

describe("HTTP - Cookie", ({test}) => {
  let cookie_header = (
    "Set-Cookie",
    "__cfduid=d90aa986407a12a7a981f1cccf8cb663a1564556010; expires=Thu, 30-Jul-20 06:53:30 GMT; path=/; domain=.strid.dev; HttpOnly; Secure",
  );

  test("Cookie.get_cookie", ({expect}) => {
    let cookie = Cookie.get_cookie(cookie_header);

    expect.equal(
      cookie,
      Cookie.{
        cookie: ("__cfduid", "d90aa986407a12a7a981f1cccf8cb663a1564556010"),
        expiration: `Session,
        domain: Some(".strid.dev"),
        path: Some("/"),
        secure: true,
        http_only: true,
      },
    );
  });

  test("Cookie.get_set_cookie_headers", ({expect}) => {
    let headers = [
      ("CF-RAY", "4feda7dcad62d137-GOT"),
      ("Server", "cloudflare"),
      ("Expect-CT", "max-age=604800"),
      (
        "report-uri",
        "https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct",
      ),
      ("Strict-Transport-Security", "max-age=15724800; includeSubDomains"),
      ("X-Frame-Options", "DENY"),
      (
        "Set-Cookie",
        "csrf_token=Cw0oHUlvPO1w0OWozvVYG8FtBxpKDl0Q; Path=/; Secure",
      ),
      (
        "Set-Cookie",
        "unifises=5oRe6xDam7Zo0sluakQ4W986JuJ3XjnL; Path=/; Secure; HttpOnly",
      ),
      (
        "Access-Control-Expose-Headers",
        "Access-Control-Allow-Origin,Access-Control-Allow-Credentials",
      ),
      ("Access-Control-Allow-Credentials", "true"),
      ("vary", "Origin"),
      (
        "Set-Cookie",
        "__cfduid=d90aa986407a12a7a981f1cccf8cb663a1564556010; expires=Thu, 30-Jul-20 06:53:30 GMT; path=/; domain=.strid.dev; HttpOnly; Secure",
      ),
      ("Connection", "close"),
      ("Content-Length", "30"),
      ("Content-Type", "application/json;charset=UTF-8"),
      ("Date", "Wed, 31 Jul 2019 06:53:31 GMT"),
    ];

    let filtered_list = Cookie.get_set_cookie_headers(headers);

    expect.list(filtered_list).toEqual([
      (
        "Set-Cookie",
        "csrf_token=Cw0oHUlvPO1w0OWozvVYG8FtBxpKDl0Q; Path=/; Secure",
      ),
      (
        "Set-Cookie",
        "unifises=5oRe6xDam7Zo0sluakQ4W986JuJ3XjnL; Path=/; Secure; HttpOnly",
      ),
      (
        "Set-Cookie",
        "__cfduid=d90aa986407a12a7a981f1cccf8cb663a1564556010; expires=Thu, 30-Jul-20 06:53:30 GMT; path=/; domain=.strid.dev; HttpOnly; Secure",
      ),
    ]);
  });

  test("Cookie.to_cookie_header", ({expect}) => {
    let cookie_header =
      [
        (
          "Set-Cookie",
          "csrf_token=Cw0oHUlvPO1w0OWozvVYG8FtBxpKDl0Q; Path=/; Secure",
        ),
        (
          "Set-Cookie",
          "unifises=5oRe6xDam7Zo0sluakQ4W986JuJ3XjnL; Path=/; Secure; HttpOnly",
        ),
        (
          "Set-Cookie",
          "__cfduid=d90aa986407a12a7a981f1cccf8cb663a1564556010; expires=Thu, 30-Jul-20 06:53:30 GMT; path=/; domain=.strid.dev; HttpOnly; Secure",
        ),
      ]
      |> CCList.map(Cookie.get_cookie)
      |> Cookie.to_cookie_header;

    expect.equal(
      cookie_header,
      (
        "Cookie",
        "csrf_token=Cw0oHUlvPO1w0OWozvVYG8FtBxpKDl0Q; unifises=5oRe6xDam7Zo0sluakQ4W986JuJ3XjnL; __cfduid=d90aa986407a12a7a981f1cccf8cb663a1564556010",
      ),
    );
  });
});

describe("HTTP - url-encoded", u => {
  u.test("Uri.get_query_param", ({expect}) => {
    let form_post_data = "grant_type=authorization_code&redirect_uri=https%3A%2F%2Fop-test%3A60004%2Fauthz_cb&code=A3wZWT2UZppKo2WGqqt";
    let form_data = UrlencodedForm.parse(form_post_data);
    let get_code = UrlencodedForm.get_param("code");

    expect.option(get_code(form_data)).toBe(Some("A3wZWT2UZppKo2WGqqt"));
  });

  u.test("decodes special chars correctly", ({expect}) => {
    let form_post_data = "username=ulrik.strid%40outlook.com&password=test";
    let form_data = UrlencodedForm.parse(form_post_data);
    let get_username = UrlencodedForm.get_param("username");

    expect.option(get_username(form_data)).toBe(
      Some("ulrik.strid@outlook.com"),
    );
  });
});
