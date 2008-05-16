-module(oauth).

-export([get/2, get/3, get/4]).
-export([post/2, post/3, post/4]).
-export([tokens/1]).
-export([params_from_string/1]).


get(URL, Consumer) ->
  fetch({get, URL, []}, Consumer).

get(URL, Consumer, {oauth_tokens, Tokens}) ->
  fetch({get, URL, []}, Consumer, Tokens);
get(URL, Consumer, Params) ->
  fetch({get, URL, Params}, Consumer, []).

get(URL, Consumer, {oauth_tokens, Tokens}, Params) ->
  fetch({get, URL, Params}, Consumer, Tokens).

post(URL, Consumer) ->
  fetch({post, URL, []}, Consumer).

post(URL, Consumer, {oauth_tokens, Tokens}) ->
  fetch({post, URL, []}, Consumer, Tokens);
post(URL, Consumer, Params) ->
  fetch({post, URL, Params}, Consumer, []).

post(URL, Consumer, {oauth_tokens, Tokens}, Params) ->
  fetch({post, URL, Params}, Consumer, Tokens).

tokens({ok, {_,_,Data}}) ->
  {ok, {oauth_tokens, params_from_string(Data)}};
tokens(Term) ->
  Term.

fetch({Method, URL, Params}, Consumer) ->
  fetch({Method, URL, Params}, Consumer, []).

fetch({Method, URL, Params}, Consumer, Tokens) ->
  SignedURL = oauth_request:url(Method, URL, Params, Consumer, Tokens),
  http:request(Method, {SignedURL, _Headers=[]}, [], []).

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
