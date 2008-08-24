-module(oauth_params).

-export([to_string/1]).
-export([to_header_string/1]).
-export([from_string/1]).

-import(lists, [map/2]).


to_string(Params) when is_list(Params) ->
  string:join(map(fun to_string/1, Params), "&");
to_string({K,V}) ->
  fmt:sprintf("%s=%s", [fmt:percent_encode(K), fmt:percent_encode(V)]).

to_header_string(Params) when is_list(Params) ->
  string:join(map(fun to_header_string/1, Params), ",");
to_header_string({K,V}) ->
  fmt:sprintf("%s=\"%s\"", [fmt:percent_encode(K), fmt:percent_encode(V)]).

from_string(Data) ->
  map(fun param_from_string/1, explode($&, Data)).

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
