-module(oauth_token_pair).

-export([new/1, new/2]).

-import(proplists, [get_value/2]).


new(Token, TokenSecret) ->
  {Token, TokenSecret}.

new(_HttpResponse={ok, {_,_,Data}}) ->
  Params = oauth_params:from_string(Data),
  {get_value("oauth_token", Params), get_value("oauth_token_secret", Params)};
new(HttpResponse) ->
  HttpResponse.
