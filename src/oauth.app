{application, oauth, [
  {description, "Erlang OAuth implementation"},
  {modules, [
    oauth,
    oauth_hmac_sha1,
    oauth_http,
    oauth_plaintext,
    oauth_rsa_sha1,
    oauth_signature,
    oauth_unix,
    oauth_uri
  ]},
  {registered, []},
  {applications, [
    kernel,
    stdlib,
    crypto,
    inets
  ]}
]}.