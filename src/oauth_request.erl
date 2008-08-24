-module(oauth_request).

-export([params_string/5]).
-export([url/5]).
-export([header/6]).


params_string(Method, URL, ExtraParams, Consumer, Tokens) ->
  oauth_params:to_string(params(Method, URL, ExtraParams, Consumer, Tokens)).

url(Method, URL, ExtraParams, Consumer, Tokens) ->
  fmt:sprintf("%s?%s", [URL, oauth_params:to_string(params(Method, URL, ExtraParams, Consumer, Tokens))]).

header(Realm, Method, URL, ExtraParams, Consumer, Tokens) ->
  SignedParams = params(Method, URL, ExtraParams, Consumer, Tokens),
  HeaderString = oauth_params:to_header_string(SignedParams),
  fmt:sprintf("Authorization: OAuth realm=\"%s\", %s", [Realm, HeaderString]).

params(Method, URL, ExtraParams, Consumer, Tokens) ->
  {Params, TokenSecret} = oauth_params(Tokens, Consumer, ExtraParams),
  [{oauth_signature, oauth_signature:new(Method, URL, Params, Consumer, TokenSecret)}|Params].

oauth_params([], Consumer, ExtraParams) ->
  {oauth_params(Consumer, ExtraParams), ""};
oauth_params(Tokens, Consumer, ExtraParams) ->
  Params = [proplists:lookup(oauth_token, Tokens)|oauth_params(Consumer, ExtraParams)],
  {Params, proplists:get_value(oauth_token_secret, Tokens)}.

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

