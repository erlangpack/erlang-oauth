-module(oauth_request).

-export([header/6, params_string/5, url/5]).


header(Realm, Method, URL, ExtraParams, Consumer, TokenPair) ->
  Params = signed_params(Method, URL, ExtraParams, Consumer, TokenPair),
  HeaderString = oauth_params:to_header_string(Params),
  HeaderValue = fmt:sprintf("OAuth realm=\"%s\", %s", [Realm, HeaderString]),
  {"Authorization", HeaderValue}.

params_string(Method, URL, ExtraParams, Consumer, TokenPair) ->
  Params = signed_params(Method, URL, ExtraParams, Consumer, TokenPair),
  oauth_params:to_string(Params).

url(Method, URL, ExtraParams, Consumer, TokenPair) ->
  Params = signed_params(Method, URL, ExtraParams, Consumer, TokenPair),
  fmt:sprintf("%s?%s", [URL, oauth_params:to_string(Params)]).

signed_params(Method, URL, ExtraParams, Consumer, TokenPair) ->
  {Params, TokenSecret} = oauth_params(TokenPair, Consumer, ExtraParams),
  [{oauth_signature, signature(Method, URL, Params, Consumer, TokenSecret)}|Params].

oauth_params({[], TokenSecret}, Consumer, ExtraParams) ->
  {oauth_params(Consumer, ExtraParams), TokenSecret};
oauth_params({Token, TokenSecret}, Consumer, ExtraParams) ->
  Params = [{oauth_token, Token}|oauth_params(Consumer, ExtraParams)],
  {Params, TokenSecret}.

oauth_params(Consumer, ExtraParams) ->
  oauth_util:proplists_merge([
    {oauth_consumer_key, oauth_consumer:key(Consumer)},
    {oauth_signature_method, oauth_consumer:signature_method(Consumer)},
    {oauth_timestamp, oauth_util:unix_timestamp()},
    {oauth_nonce, oauth_util:nonce()},
    {oauth_version, "1.0"}
  ], ExtraParams).

signature(RequestMethod, URL, Params, Consumer, TokenSecret) ->
  ConsumerSecret = oauth_consumer:secret(Consumer),
  case proplists:get_value(oauth_signature_method, Params) of
    "PLAINTEXT" ->
      oauth_plaintext:signature(ConsumerSecret, TokenSecret);
    "HMAC-SHA1" ->
      BaseString = oauth_base:string(RequestMethod, URL, Params),
      oauth_hmac:signature(BaseString, ConsumerSecret, TokenSecret)
  end.