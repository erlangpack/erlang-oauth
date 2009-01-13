-module(oauth_plaintext).

-export([signature/2]).


signature(CS, TS) ->
  oauth_uri:encode(oauth_uri:calate("&", [CS, TS])).
