-module(oauth_request).

-export([url/5]).
-export([header/6]).

% for testing:
-export([plaintext_signature/2]).
-export([hmac_sha1_signature/3]).
-export([hmac_sha1_base_string/3]).
-export([hmac_sha1_normalize/1]).
-export([params_to_header_string/1]).

-import(fmt, [sprintf/2, percent_encode/1]).
-import(lists, [map/2]).
-import(oauth_util, [implode/2]).


url(Method, URL, ExtraParams, Consumer, Tokens) ->
  {Params, TokenSecret} = oauth_params(Tokens, Consumer, ExtraParams),
  signed_url(Method, URL, Params, Consumer, TokenSecret).

header(Realm, Method, URL, ExtraParams, Consumer, Tokens) ->
  {Params, TokenSecret} = oauth_params(Tokens, Consumer, ExtraParams),
  signed_header(Realm, Method, URL, Params, Consumer, TokenSecret).

oauth_params([], Consumer, ExtraParams) ->
  {"", oauth_params(Consumer, ExtraParams)};
oauth_params(Tokens, Consumer, ExtraParams) ->
  Params = [proplists:lookup(oauth_token, Tokens)|oauth_params(Consumer, ExtraParams)],
  {proplists:get_value(oauth_token_secret, Tokens), Params}.

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

signed_url(Method, URL, Params, Consumer, TokenSecret) ->
  SignedParams = signed_params(Method, URL, Params, Consumer, TokenSecret),
  sprintf("%s?%s", [URL, params_to_string(SignedParams)]).

signed_header(Realm, Method, URL, Params, Consumer, TokenSecret) ->
  SignedParams = signed_params(Method, URL, Params, Consumer, TokenSecret),
  sprintf("Authorization: OAuth realm=\"%s\", %s", [Realm, params_to_header_string(SignedParams)]).

signed_params(Method, URL, Params, Consumer, TokenSecret) ->
  [{oauth_signature, signature(Method, URL, Params, Consumer, TokenSecret)}|Params].

signature(Method, URL, Params, Consumer, TokenSecret) ->
  ConsumerSecret = oauth_consumer:secret(Consumer),
  case signature_method(Params) of
    "PLAINTEXT" ->
      plaintext_signature(ConsumerSecret, TokenSecret);
    "HMAC-SHA1" ->
      MethodString = string:to_upper(atom_to_list(Method)),
      BaseString = hmac_sha1_base_string(MethodString, URL, Params),
      hmac_sha1_signature(BaseString, ConsumerSecret, TokenSecret)
  end.

signature_method(Params) ->
  proplists:get_value(oauth_signature_method, Params).

plaintext_signature(ConsumerSecret, TokenSecret) ->
  percent_encode(sprintf("%s&%s", [percent_encode(ConsumerSecret), percent_encode(TokenSecret)])).

hmac_sha1_signature(BaseString, ConsumerSecret, TokenSecret) ->
  base64:encode_to_string(crypto:sha_mac(hmac_sha1_key(ConsumerSecret, TokenSecret), BaseString)).

hmac_sha1_key(ConsumerSecret, TokenSecret) ->
  sprintf("%s&%s", [percent_encode(ConsumerSecret), percent_encode(TokenSecret)]).

hmac_sha1_base_string(MethodString, URL, Params) ->
  implode($&, map(fun fmt:percent_encode/1, [MethodString, URL, hmac_sha1_normalize(Params)])).

hmac_sha1_normalize(Params) ->
  params_to_string(lists:sort(fun({K,X},{K,Y}) -> X < Y; ({A,_},{B,_}) -> A < B end, Params)).

params_to_string(Params) ->
  implode($&, map(fun param_to_string/1, Params)).

param_to_string({K,V}) ->
  sprintf("%s=%s", [percent_encode(K), percent_encode(V)]).

params_to_header_string(Params) ->
  implode($,, map(fun param_to_header_string/1, Params)).

param_to_header_string({K,V}) ->
  sprintf("%s=\"%s\"", [percent_encode(K), percent_encode(V)]).
