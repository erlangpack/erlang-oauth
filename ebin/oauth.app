{application, oauth, [
  {description, "An Erlang OAuth 1.0 implementation"},
  {vsn, "1.0.1"},
  {modules, [
    oauth,
    oauth_client,
    oauth_hmac_sha1,
    oauth_http,
    oauth_plaintext,
    oauth_rsa_sha1,
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
