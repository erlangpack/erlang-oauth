-module(oauth).

-export([get/2, get/3, get/4, post/2, post/3, post/4]).


get(URL, Consumer) ->
  get(URL, Consumer, {[], []}, []).

get(URL, Consumer, Params) when is_list(Params) ->
  get(URL, Consumer, {[], []}, Params);
get(URL, Consumer, TokenPair) ->
  get(URL, Consumer, TokenPair, []).

get(URL, Consumer, TokenPair, Params) ->
  Request = oauth_request:new("GET", URL, Params),
  RequestURL = oauth_request:to_url(Request, Consumer, TokenPair),
  http:request(get, {RequestURL, []}, [{autoredirect, false}], []).

post(URL, Consumer) ->
  post(URL, Consumer, {[], []}, []).

post(URL, Consumer, Params) when is_list(Params) ->
  post(URL, Consumer, {[], []}, Params);
post(URL, Consumer, TokenPair) ->
  post(URL, Consumer, TokenPair, []).

post(URL, Consumer, TokenPair, Params) ->
  Request = oauth_request:new("POST", URL, Params),
  Data = oauth_request:to_string(Request, Consumer, TokenPair),
  MimeType = "application/x-www-form-urlencoded",
  http:request(post, {URL, [], MimeType, Data}, [{autoredirect, false}], []).
