-module(oauth_hmac).

-export([base_string/3, normalize/1, signature/3]).

-import(fmt, [percent_encode/1]).


signature({Method, URL, Params}, ConsumerSecret, TokenSecret) ->
  signature(base_string(Method, URL, Params), ConsumerSecret, TokenSecret);
signature(BaseString, ConsumerSecret, TokenSecret) ->
  b64(crypto:sha_mac(key(ConsumerSecret, TokenSecret), BaseString)).

base_string(Method, URL, Params) when is_list(Method) ->
  Unencoded = [Method, oauth_uri:normalize(URL), normalize(Params)],
  string:join([percent_encode(Str) || Str <- Unencoded], "&").

normalize(Params) ->
  StringParams = lists:map(fun({K, V}) when is_atom(K) -> {atom_to_list(K), V}; (I) -> I end, Params),
  oauth_params:to_string(sort(StringParams)).

sort(Params) ->
  lists:sort(fun({K,X},{K,Y}) -> X < Y; ({A,_},{B,_}) -> A < B end, Params).

key(ConsumerSecret, TokenSecret) ->
  fmt:sprintf("%s&%s", [percent_encode(ConsumerSecret), percent_encode(TokenSecret)]).

b64(Data) ->
  base64:encode_to_string(Data).
