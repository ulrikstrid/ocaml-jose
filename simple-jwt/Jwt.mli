type payload = Yojson.Safe.t

val make : payload:payload -> jwk:Jose.Jwk.priv Jose.Jwk.t -> string

val validate : token:string -> jwk:'a Jose.Jwk.t -> payload option

val make_jwk : ?kind:[`Key | `PEM | `JSON] -> string -> ('a Jose.Jwk.t, [> `Msg of string]) result