-module(oauth_params).

-export([from_string/1, to_string/1, to_header_string/1]).


from_string(Data) ->
  [percent_decode(break_at($=, P)) || P <- string:tokens(Data, "&")].

to_string(Params) ->
  to_string(Params, "%s=%s", "&").

to_string(Params, Fmt, Sep) ->
  string:join([oauth_util:esprintf(Fmt, Param) || Param <- Params], Sep).

to_header_string(Params) ->
  to_string(Params, "%s=\"%s\"", ",").

percent_decode({K, V}) ->
  {oauth_util:percent_decode(K), oauth_util:percent_decode(V)}.

break_at(Sep, Chars) ->
  case lists:splitwith(fun(C) -> C =/= Sep end, Chars) of
    Result={_, []} ->
      Result;
    {Before, [Sep|After]} ->
      {Before, After}
  end.
