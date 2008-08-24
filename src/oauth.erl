-module(oauth).

-export([get/2, get/3, get/4]).
-export([post/2, post/3, post/4]).
-export([tokens/1]).
-export([token/1]).
-export([token_secret/1]).


get(URL, Consumer) ->
  get(URL, Consumer, [], []).

get(URL, Consumer, {oauth_tokens, Tokens}) ->
  get(URL, Consumer, Tokens, []);
get(URL, Consumer, Params) when is_list(Params)->
  get(URL, Consumer, [], Params).

get(URL, Consumer, {oauth_tokens, Tokens}, Params) ->
  get(URL, Consumer, Tokens, Params);
get(URL, Consumer, Tokens, Params) when is_list(Tokens) ->
  http:request(oauth_request:url("GET", URL, Params, Consumer, Tokens)).

post(URL, Consumer) ->
  post(URL, Consumer, [], []).

post(URL, Consumer, {oauth_tokens, Tokens}) ->
  post(URL, Consumer, Tokens, []);
post(URL, Consumer, Params) when is_list(Params) ->
  post(URL, Consumer, [], Params).

post(URL, Consumer, {oauth_tokens, Tokens}, Params) ->
  post(URL, Consumer, Tokens, Params);
post(URL, Consumer, Tokens, Params) when is_list(Tokens) ->
  SignedParamsString = oauth_request:params_string("POST", URL, Params, Consumer, Tokens),
  Request = {URL, [], "application/x-www-form-urlencoded", SignedParamsString},
  http:request(post, Request, [], []).

tokens({ok, {_,_,Data}}) ->
  {ok, {oauth_tokens, oauth_params:from_string(Data)}};
tokens(Term) ->
  Term.

token({oauth_tokens, Tokens}) ->
  proplists:get_value(oauth_token, Tokens).

token_secret({oauth_tokens, Tokens}) ->
  proplists:get_value(oauth_token_secret, Tokens).
