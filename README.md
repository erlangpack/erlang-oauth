# An Erlang OAuth implementation

## Quick start (client usage)

    $ make
    ...
    $ erl -pa ebin -s crypto -s inets
    ...
    1> Consumer = {"key", "secret", hmac_sha1}.
    ...
    2> RequestTokenURL = "http://term.ie/oauth/example/request_token.php".
    ...
    3> {ok, RequestTokenResponse} = oauth:get(RequestTokenURL, [], Consumer).
    ...
    4> RequestTokenParams = oauth:params_decode(RequestTokenResponse).
    ...
    5> RequestToken = oauth:token(RequestTokenParams).
    ...
    6> RequestTokenSecret = oauth:token_secret(RequestTokenParams).
    ...
    7> AccessTokenURL = "http://term.ie/oauth/example/access_token.php".
    ...
    8> {ok, AccessTokenResponse} = oauth:get(AccessTokenURL, [], Consumer, RequestToken, RequestTokenSecret).
    ...
    9> AccessTokenParams = oauth:params_decode(AccessTokenResponse).
    ...
    10> AccessToken = oauth:token(AccessTokenParams).
    ...
    11> AccessTokenSecret = oauth:token_secret(AccessTokenParams).
    ...
    12> URL = "http://term.ie/oauth/example/echo_api.php".
    ...
    13> {ok, Response} = oauth:get(URL, [{"hello", "world"}], Consumer, AccessToken, AccessTokenSecret).
    ...
    14> oauth:params_decode(Response).
    ...

## Notes

Consumer credentials are represented as follows:

    {Key::string(), Secret::string(), plaintext}

    {Key::string(), Secret::string(), hmac_sha1}

    {Key::string(), RSAPrivateKeyPath::string(), rsa_sha1}  % client side

    {Key::string(), RSACertificatePath::string(), rsa_sha1}  % server side


Erlang/OTP R14B or greater is required for RSA-SHA1

The percent encoding/decoding implementations are based on [ibrowse](https://github.com/cmullaparthi/ibrowse)

Example client/server code: [github.com/tim/erlang-oauth-examples](https://github.com/tim/erlang-oauth-examples)

Unit tests: [github.com/tim/erlang-oauth-tests](https://github.com/tim/erlang-oauth-tests)
