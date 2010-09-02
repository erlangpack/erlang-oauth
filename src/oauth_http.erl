-module(oauth_http).

-export([get/1, post/2, response_params/1, response_body/1, response_code/1]).


get(Url) ->
  request(get, Url, _Headers=[], _Body=[], _Options=[]).

post(Url, Data) ->
  request(post, Url, _Headers=[], Data, _Options=[{content_type, "application/x-www-form-urlencoded"}]).

request(Method, Url, Headers, Body, Options) ->
  ibrowse:send_req_httpc(Url, Headers, Method, Body, Options, 30000).

response_params(Response) ->
  oauth_uri:params_from_string(response_body(Response)).

response_body({{_, _, _}, _, Body}) ->
  Body.

response_code({{_, Code, _}, _, _}) ->
  Code.
