-module(oauth_termie).

-compile(export_all).

% cf. http://term.ie/oauth/example/


test() ->
  test(oauth_consumer:new("key", "secret", "HMAC-SHA1")).

test(Consumer) ->
  RequestTokenURL = "http://term.ie/oauth/example/request_token.php",
  test(Consumer, tee(oauth_token_pair:new(oauth:get(RequestTokenURL, Consumer)))).

test(Consumer, RequestTokenPair) ->
  AccessTokenURL = "http://term.ie/oauth/example/access_token.php",
  AccessTokenResponse = tee(oauth_token_pair:new(oauth:get(AccessTokenURL, Consumer, RequestTokenPair))),
  test(Consumer, AccessTokenResponse, [{bar, "baz"}, {method, "foo"}]).

test(Consumer, AccessTokenPair, EchoParams) ->
  EchoURL = "http://term.ie/oauth/example/echo_api.php",
  {ok, {_,_,Data}} = tee(oauth:get(EchoURL, Consumer, AccessTokenPair, EchoParams)),
  tee(lists:keysort(1, oauth_params:from_string(Data))).

tee(X) ->
  error_logger:info_msg("~p~n~n", [X]), X.
