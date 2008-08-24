-module(oauth_plaintext).

-export([signature/2]).


signature(ConsumerSecret, TokenSecret) ->
  encode(fmt:sprintf("%s&%s", [encode(ConsumerSecret), encode(TokenSecret)])).

encode(String) ->
  fmt:percent_encode(String).