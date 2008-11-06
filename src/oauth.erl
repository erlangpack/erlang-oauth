-module(oauth).

-export([get/2, get/3, get/4, post/2, post/3, post/4]).


get(URL, Consumer) ->
  get(URL, Consumer, {[], []}, []).

get(URL, Consumer, Params) when is_list(Params) ->
  get(URL, Consumer, {[], []}, Params);
get(URL, Consumer, TokenPair) ->
  get(URL, Consumer, TokenPair, []).

get(URL, Consumer, TokenPair, Params) ->
  oauth_http:get(oauth_request:url("GET", URL, Params, Consumer, TokenPair)).

post(URL, Consumer) ->
  post(URL, Consumer, {[], []}, []).

post(URL, Consumer, Params) when is_list(Params) ->
  post(URL, Consumer, {[], []}, Params);
post(URL, Consumer, TokenPair) ->
  post(URL, Consumer, TokenPair, []).

post(URL, Consumer, TokenPair, Params) ->
  Data = oauth_request:params_string("POST", URL, Params, Consumer, TokenPair),
  oauth_http:post(URL, Data).
