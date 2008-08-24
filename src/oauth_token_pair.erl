-module(oauth_token_pair).

-export([new/2]).
-export([new/1]).


new(Token, TokenSecret) ->
  {Token, TokenSecret}.

new(_HttpResponse={ok, {_,_,Data}}) ->
  new_from_params(oauth_params:from_string(Data));
new(HttpResponse) ->
  HttpResponse.

new_from_params(List) ->
  new(get(oauth_token, List), get(oauth_token_secret, List)).

get(Key, List) ->
  proplists:get_value(Key, List).