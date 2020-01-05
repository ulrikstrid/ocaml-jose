module RResult = {
  let map = (fn, r) => {
    switch (r) {
    | Ok(v) => Ok(fn(v))
    | Error(e) => Error(e)
    };
  };

  let map_error = (fn, r) => {
    switch (r) {
    | Ok(r) => Ok(r)
    | Error(e) => Error(fn(e))
    };
  };

  let flat_map = (fn, r) => {
    switch (r) {
    | Ok(v) => fn(v)
    | Error(e) => Error(e)
    };
  };

  let both = (a, b) =>
    switch (a, b) {
    | (Ok(a), Ok(b)) => Ok((a, b))
    | (Error(e), _) => Error(e)
    | (_, Error(e)) => Error(e)
    };
};

module RList = {
  let rec find_opt = p =>
    fun
    | [] => None
    | [x, ...l] =>
      if (p(x)) {
        Some(x);
      } else {
        find_opt(p, l);
      };
};

module RBase64 = {
  let base64_url_encode =
    Base64.encode(~pad=false, ~alphabet=Base64.uri_safe_alphabet);
  let base64_url_decode =
    Base64.decode(~pad=false, ~alphabet=Base64.uri_safe_alphabet);
};
