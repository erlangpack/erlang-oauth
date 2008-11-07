-module(oauth_base).

-export([string/3, normalize/1]).


string(Method, URL, Params) when is_list(Method) ->
  Unencoded = [Method, oauth_uri:normalize(URL), normalize(Params)],
  string:join([fmt:percent_encode(Str) || Str <- Unencoded], "&").

normalize(Params) ->
  oauth_params:to_string(sort([to_string(KV) || KV <- Params])).

sort(Params) ->
  lists:sort(fun({K,X},{K,Y}) -> X < Y; ({A,_},{B,_}) -> A < B end, Params).

to_string({K, V}) when is_atom(K) ->
  {atom_to_list(K), V};
to_string({K, V}) when is_list(K) ->
  {K, V}.