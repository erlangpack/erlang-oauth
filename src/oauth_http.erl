-module(oauth_http).

-export([get/1]).
-export([post/2]).


get(URL) ->
  http:request(URL).

post(URL, {MimeType, Data}) ->
  http:request(post, {URL, [], MimeType, Data}, [], []).
