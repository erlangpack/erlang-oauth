An Erlang OAuth implementation.

Quick start (client usage):

  $ make
  ...
  $ erl -pa ebin -s crypto -s inets
  Erlang (BEAM) emulator version 5.6.5 [source] [smp:2] [async-threads:0] [kernel-poll:false]

  Eshell V5.6.5  (abort with ^G)
  1> Consumer = {"key", "secret", hmac_sha1}.
  ...
  2> RequestTokenURL = "http://term.ie/oauth/example/request_token.php".
  ...
  3> {ok, ResponseR} = oauth:get(RequestTokenURL, [], Consumer, "", "").
  ...
  4> ParamsR = oauth_http:response_params(ResponseR).
  ...
  5> TokenR = oauth:token(ParamsR).
  ...
  6> TokenSecretR = oauth:token_secret(ParamsR).
  ...
  7> AccessTokenURL = "http://term.ie/oauth/example/access_token.php".
  ...
  6> {ok, ResponseA} = oauth:get(AccessTokenURL, [], Consumer, TokenR, TokenSecretR).
  ...


Erlang R12B-5 is required for generating RSA-SHA1 signatures.

RSA-SHA1 signature verification is not yet implemented.
