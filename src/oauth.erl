-module(oauth).

-export([get/2, get/3, get/4]).
-export([post/2, post/3, post/4]).
-export([tokens/1]).
-export([token/1]).
-export([token_secret/1]).
-export([params_from_string/1]).


get(URL, Consumer) ->
  get(URL, Consumer, [], []).

get(URL, Consumer, {oauth_tokens, Tokens}) ->
  get(URL, Consumer, Tokens, []);
get(URL, Consumer, Params) when is_list(Params)->
  get(URL, Consumer, [], Params).

get(URL, Consumer, {oauth_tokens, Tokens}, Params) ->
  get(URL, Consumer, Tokens, Params);
get(URL, Consumer, Tokens, Params) when is_list(Tokens) ->
  http:request(oauth_request:url(get, URL, Params, Consumer, Tokens)).

post(URL, Consumer) ->
  post(URL, Consumer, [], []).

post(URL, Consumer, {oauth_tokens, Tokens}) ->
  post(URL, Consumer, Tokens, []);
post(URL, Consumer, Params) when is_list(Params) ->
  post(URL, Consumer, [], Params).

post(URL, Consumer, {oauth_tokens, Tokens}, Params) ->
  post(URL, Consumer, Tokens, Params);
post(URL, Consumer, Tokens, Params) when is_list(Tokens) ->
  SignedParamsString = oauth_request:params_string(post, URL, Params, Consumer, Tokens),
  Request = {URL, [], "application/x-www-form-urlencoded", SignedParamsString},
  http:request(post, Request, [], []).

tokens({ok, {_,_,Data}}) ->
  {ok, {oauth_tokens, params_from_string(Data)}};
tokens(Term) ->
  Term.

token({oauth_tokens, Tokens}) ->
  proplists:get_value(oauth_token, Tokens).

token_secret({oauth_tokens, Tokens}) ->
  proplists:get_value(oauth_token_secret, Tokens).

params_from_string(Data) ->
  lists:map(fun param_from_string/1, explode($&, Data)).

param_from_string(Data) when is_list(Data) ->
  param_from_string(break_at($=, Data));
param_from_string({K, V}) ->
  {list_to_atom(oauth_util:percent_decode(K)), oauth_util:percent_decode(V)}.

explode(_Sep, []) ->
  [];
explode(Sep, Chars) ->
  explode(Sep, break_at(Sep, Chars), []).

explode(_Sep, {Param, []}, Params) ->
  lists:reverse([Param|Params]);
explode(Sep, {Param, Etc}, Params) ->
  explode(Sep, break_at(Sep, Etc), [Param|Params]).

break_at(Sep, Chars) ->
  case lists:splitwith(fun(C) -> C =/= Sep end, Chars) of
    Result={_, []} ->
      Result;
    {Before, [Sep|After]} ->
      {Before, After}
  end.
