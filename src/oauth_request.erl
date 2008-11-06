-module(oauth_request).

-export([header/6, params_string/5, url/5]).


params_string(Method, URL, ExtraParams, Consumer, TokenPair) ->
  oauth_params:to_string(params(Method, URL, ExtraParams, Consumer, TokenPair)).

url(Method, URL, ExtraParams, Consumer, TokenPair) ->
  fmt:sprintf("%s?%s", [URL, oauth_params:to_string(params(Method, URL, ExtraParams, Consumer, TokenPair))]).

header(Realm, Method, URL, ExtraParams, Consumer, TokenPair) ->
  SignedParams = params(Method, URL, ExtraParams, Consumer, TokenPair),
  HeaderString = oauth_params:to_header_string(SignedParams),
  {"Authorization", 
   fmt:sprintf("OAuth realm=\"%s\", %s", [Realm, HeaderString])}.

params(Method, URL, ExtraParams, Consumer, TokenPair) ->
  {Params, TokenSecret} = oauth_params(TokenPair, Consumer, ExtraParams),
  [{oauth_signature, oauth_signature:new(Method, URL, Params, Consumer, TokenSecret)}|Params].

oauth_params({[], TokenSecret}, Consumer, ExtraParams) ->
  {oauth_params(Consumer, ExtraParams), TokenSecret};
oauth_params({Token, TokenSecret}, Consumer, ExtraParams) ->
  Params = [{oauth_token, Token}|oauth_params(Consumer, ExtraParams)],
  {Params, TokenSecret}.

oauth_params(Consumer, ExtraParams) ->
  proplists_merge([
    {oauth_consumer_key, oauth_consumer:key(Consumer)},
    {oauth_signature_method, oauth_consumer:signature_method(Consumer)},
    {oauth_timestamp, oauth_util:unix_timestamp()},
    {oauth_nonce, oauth_util:nonce()},
    {oauth_version, "1.0"}
  ], ExtraParams).

proplists_merge({K,V}, Merged) ->
  case proplists:is_defined(K, Merged) of
    true ->
      Merged;
    false ->
      [{K,V}|Merged]
  end;
proplists_merge(A, B) ->
  lists:foldl(fun proplists_merge/2, A, B).

