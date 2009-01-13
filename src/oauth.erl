-module(oauth).

-export([get/5, post/5, token/1, token_secret/1, uri/2, header/1, signed_params/6]).


get(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  SignedParams = signed_params("GET", URL, ExtraParams, Consumer, Token, TokenSecret),
  oauth_http:get(uri(URL, SignedParams)).

post(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  SignedParams = signed_params("GET", URL, ExtraParams, Consumer, Token, TokenSecret),
  oauth_http:post(URL, oauth_uri:params_to_string(SignedParams)).

token(Params) ->
  proplists:get_value("oauth_token", Params).

token_secret(Params) ->
  proplists:get_value("oauth_token_secret", Params).

uri(Base, []) ->
  Base;
uri(Base, Params) ->
  lists:concat([Base, "?", oauth_uri:params_to_string(Params)]).

header(Params) ->
  {"Authorization", "OAuth " ++ oauth_uri:params_to_header_string(Params)}.

signed_params(Method, URL, ExtraParams, Consumer, Token, TokenSecret) ->
  Params = token_param(Token, params(Consumer, ExtraParams)),
  [{"oauth_signature", oauth_signature:value(Method, URL, Params, Consumer, TokenSecret)}|Params].

token_param("", Params) ->
  Params;
token_param(Token, Params) ->
  [{"oauth_token", Token}|Params].

params(_Consumer={Key, _, SigMethod}, Params) ->
  Nonce = base64:encode_to_string(crypto:rand_bytes(32)), % cf. ruby-oauth
  params(Key, SigMethod, oauth_unix:timestamp(), Nonce, Params).

params(ConsumerKey, SigMethod, Timestamp, Nonce, Params) -> [
  {"oauth_version", "1.0"},
  {"oauth_nonce", Nonce},
  {"oauth_timestamp", integer_to_list(Timestamp)},
  {"oauth_signature_method", oauth_signature:method_to_string(SigMethod)},
  {"oauth_consumer_key", ConsumerKey} | Params].
