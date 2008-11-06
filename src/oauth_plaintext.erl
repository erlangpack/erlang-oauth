-module(oauth_plaintext).

-export([signature/2]).


signature(ConsumerSecret, TokenSecret) ->
  Encoded = oauth_util:esprintf("%s&%s", [ConsumerSecret, TokenSecret]),
  fmt:percent_encode(Encoded).
