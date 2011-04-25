-module(oauth_http).

-export([get/1, get/2, post/2, post/3, response_params/1, response_body/1, response_code/1]).

-type http_status() :: {string(), integer(), string()}.

-spec get(string()) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
get(URL) ->
  get(URL, []).

-spec get(string(), [proplists:property()]) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
get(URL, Options) ->
  request(get, {URL, []}, Options).

-spec post(string(), term()) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
post(URL, Data) ->
  post(URL, Data, []).

-spec post(string(), term(), [proplists:property()]) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
post(URL, Data, Options) ->
  request(post, {URL, [], "application/x-www-form-urlencoded", Data}, Options).

-spec request(get|post, tuple(), [proplists:property()]) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
request(Method, Request, Options) ->
  httpc:request(Method, Request, [{autoredirect, false}, {ssl, [{ssl_imp, old}]}], Options).

-spec response_params({http_status(), [{string(), string()}], string()}) -> [{string(), string()}].
response_params(Response) ->
  oauth_uri:params_from_string(response_body(Response)).

-spec response_body({http_status(), [{string(), string()}], string()}) -> string().
response_body({{_, _, _}, _, Body}) ->
  Body.

-spec response_code({http_status(), [{string(), string()}], string()}) -> integer().
response_code({{_, Code, _}, _, _}) ->
  Code.
