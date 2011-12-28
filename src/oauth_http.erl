-module(oauth_http).

-export([get/1, get/2, post/2, post/3, delete/1, delete/2]).

-type http_status() :: {string(), integer(), string()}.

-spec get(string()) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
get(URL) ->
  get(URL, []).

-spec get(string(), [proplists:property()]) -> ibrowse:response().
get(URL, Options) ->
  ibrowse:send_req(URL, [], get, [], [{ssl_options, [{ssl_imp, old}]}|Options]).

-spec post(string(), term()) -> ibrowse:response().
post(URL, Data) ->
  post(URL, Data, []).

-spec post(string(), term(), [proplists:property()]) -> ibrowse:response().
post(URL, Data, Options) ->
  ibrowse:send_req(URL, [], get, Data, [{ssl_options, [{ssl_imp, old}]},
                                        {content_type, "application/x-www-form-urlencoded"} | Options]).
  
-spec delete(string()) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
delete(URL) ->
  delete(URL, []).

-spec delete(string(), [proplists:property()]) -> {ok, {Status::http_status(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
delete(URL, Options) ->
  ibrowse:send_req(URL, [], delete, [], [{ssl_options, [{ssl_imp, old}]}|Options]).