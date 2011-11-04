An Erlang OAuth implementation.

Quick start (client usage):

  $ make
  ...
  $ erl -pa ebin -s crypto -s inets -s ssl
  ...
  1> rr(oauth).
  ...
  2> Consumer = #oauth_consumer{key = "key", secret = "secret", method = hmac_sha1}.
  ...
  3> RequestTokenURL = "http://term.ie/oauth/example/request_token.php".
  ...
  4> {ok, RequestTokenResponse} = oauth:get(RequestTokenURL, [], Consumer).
  ...
  5> RequestTokenParams = oauth:params_decode(RequestTokenResponse).
  ...
  6> RequestToken = oauth:token(RequestTokenParams).
  ...
  7> RequestTokenSecret = oauth:token_secret(RequestTokenParams).
  ...
  8> AccessTokenURL = "http://term.ie/oauth/example/access_token.php".
  ...
  9> {ok, AccessTokenResponse} = oauth:get(AccessTokenURL, [], Consumer, RequestToken, RequestTokenSecret).
  ...
  10> AccessTokenParams = oauth:params_decode(AccessTokenResponse).
  ...
  11> AccessToken = oauth:token(AccessTokenParams).
  ...
  12> AccessTokenSecret = oauth:token_secret(AccessTokenParams).
  ...
  13> URL = "http://term.ie/oauth/example/echo_api.php".
  ...
  14> {ok, Response} = oauth:get(URL, [{"hello", "world"}], Consumer, AccessToken, AccessTokenSecret).
  ...
  15> oauth:params_decode(Response).
  ...


Consumer credentials are represented as follows:

  #oauth_consumer{key = Key::string(), secret = Secret::string(), method = plaintext}

  #oauth_consumer{key = Key::string(), key = Secret::string(), key = hmac_sha1}

  #oauth_consumer{key = Key::string(), key = RSAPrivateKeyPath::string(), key = rsa_sha1}  % client side

  #oauth_consumer{key = Key::string(), key = RSACertificatePath::string(), key = rsa_sha1}  % server side


The percent encoding/decoding implementations are based on those found in
the ibrowse library, written by Chandrashekhar Mullaparthi.

Example client/server code is at http://github.com/tim/erlang-oauth-examples.

Unit tests are at http://github.com/tim/erlang-oauth-tests.

Erlang/OTP R14B or greater is required for RSA-SHA1.
