# erlang-oauth

An Erlang implementation of [The OAuth 1.0 Protocol](https://tools.ietf.org/html/rfc5849).

Functions for generating signatures (client side), verifying signatures (server side),
and some convenience functions for making OAuth HTTP requests (client side).


## Erlang/OTP compatibility

Erlang/OTP 21 or greater.


## Rebar3 compatibility

Add erlang-oauth as a dependency to your rebar.config file like this:

    {deps, [
      {oauth, {git, "https://github.com/tim/erlang-oauth.git"}}
    ]}.

Consult the rebar docs for more information.


## Quick start (client usage)

    $ erl -make
    Recompile: src/oauth
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


## OAuth consumer representation

Consumers are represented using tuples:

```erlang
{Key::string(), Secret::string(), plaintext}

{Key::string(), Secret::string(), hmac_sha1}

{Key::string(), RSAPrivateKeyPath::string(), rsa_sha1}  % client side

{Key::string(), RSACertificatePath::string(), rsa_sha1}  % server side
```


## Other notes

This implementation should be compatible with the signature algorithms
presented in [RFC5849 - The OAuth 1.0 Protocol](http://tools.ietf.org/html/rfc5849),
and [OAuth Core 1.0 Revision A](http://oauth.net/core/1.0a/). It is *not* intended
to cover [OAuth 2.0](http://oauth.net/2/).

This is *not* a "plug and play" server implementation. In order to implement OAuth
correctly as a provider you have more work to do: token storage, nonce and timestamp
verification etc.

This is *not* a "bells and whistles" HTTP client. If you need fine grained control
over your HTTP requests or you prefer to use something other than inets/httpc then you
will need to assemble the requests yourself. Use `oauth:sign/6` to generate a list of
signed OAuth parameters, `oauth:uri_params_encode/1` or `oauth:header_params_encode/1` to
encode the parameters, and then assemble the request using your HTTP client of choice.

The percent encoding/decoding implementations are based on [ibrowse](https://github.com/cmullaparthi/ibrowse)

Example client/server code: [github.com/tim/erlang-oauth-examples](https://github.com/tim/erlang-oauth-examples)


## License

This project is licensed under the terms of the [MIT license](https://opensource.org/licenses/MIT).
