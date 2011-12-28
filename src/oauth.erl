-module(oauth).

-export(
  [ get/5
  , get/6
  , header/1
  , post/5
  , post/6
  , delete/5
  , delete/6
  , signature/5
  , signature_base_string/3
  , signed_params/6
  , token/1
  , token_param/2
  , token_secret/1
  , token_secret_param/2
  , uri/2
  , verify/6
  ]).

-spec get(string(), [proplists:property()], oauth_client:consumer(), string(), string()) -> {ok, {Status::tuple(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
get(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  get(URL, ExtraParams, Consumer, Token, TokenSecret, []).

-spec get(string(), [proplists:property()], oauth_client:consumer(), string(), string(), [proplists:property()]) -> {ok, {Status::tuple(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
get(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = signed_params("GET", URL, ExtraParams, Consumer, Token, TokenSecret),
  oauth_http:get(uri(URL, SignedParams), HttpcOptions).

-spec post(string(), [proplists:property()], oauth_client:consumer(), string(), string()) -> {ok, {Status::tuple(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
post(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  post(URL, ExtraParams, Consumer, Token, TokenSecret, []).

-spec post(string(), [proplists:property()], oauth_client:consumer(), string(), string(), [proplists:property()]) -> {ok, {Status::tuple(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
post(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = signed_params("POST", URL, ExtraParams, Consumer, Token, TokenSecret),
  oauth_http:post(URL, oauth_uri:params_to_string(SignedParams), HttpcOptions).

-spec delete(string(), [proplists:property()], oauth_client:consumer(), string(), string()) -> {ok, {Status::tuple(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
delete(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  delete(URL, ExtraParams, Consumer, Token, TokenSecret, []).

-spec delete(string(), [proplists:property()], oauth_client:consumer(), string(), string(), [proplists:property()]) -> {ok, {Status::tuple(), Headers::[{string(), string()}], Body::string()}} | {error, term()}.
delete(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = signed_params("POST", URL, ExtraParams, Consumer, Token, TokenSecret),
  oauth_http:delete(uri(URL, SignedParams), HttpcOptions).

-spec uri(string(), [proplists:property()]) -> string().
uri(Base, []) ->
  Base;
uri(Base, Params) ->
  lists:concat([Base, "?", oauth_uri:params_to_string(Params)]).

-spec header([{string(), string()}]) -> {string(), string()}.
header(Params) ->
  {"Authorization", "OAuth " ++ oauth_uri:params_to_header_string(Params)}.

-spec token([proplists:property()]) -> string().
token(Params) ->
  proplists:get_value("oauth_token", Params).

-spec token_secret([proplists:property()]) -> string().
token_secret(Params) ->
  proplists:get_value("oauth_token_secret", Params).

-spec verify(string(), string(), string(), [proplists:property()], oauth_client:consumer(), string()) -> boolean().
verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret) ->
  case signature_method(Consumer) of
    plaintext ->
      oauth_plaintext:verify(Signature, consumer_secret(Consumer), TokenSecret);
    hmac_sha1 ->
      BaseString = signature_base_string(HttpMethod, URL, Params),
      oauth_hmac_sha1:verify(Signature, BaseString, consumer_secret(Consumer), TokenSecret);
    rsa_sha1 ->
      BaseString = signature_base_string(HttpMethod, URL, Params),
      oauth_rsa_sha1:verify(Signature, BaseString, consumer_secret(Consumer))
  end.

-spec signed_params(string(), string(), [proplists:property()], oauth_client:consumer(), string(), string()) -> [{string(), string()}].
signed_params(HttpMethod, URL, ExtraParams, Consumer, Token, TokenSecret) ->
  Params = token_param(Token, params(Consumer, ExtraParams)),
  [{"oauth_signature", signature(HttpMethod, URL, Params, Consumer, TokenSecret)}|Params].

-spec signature(string(), string(), [proplists:property()], oauth_client:consumer(), string()) -> string().
signature(HttpMethod, URL, Params, Consumer, TokenSecret) ->
  case signature_method(Consumer) of
    plaintext ->
      oauth_plaintext:signature(consumer_secret(Consumer), TokenSecret);
    hmac_sha1 ->
      BaseString = signature_base_string(HttpMethod, URL, Params),
      oauth_hmac_sha1:signature(BaseString, consumer_secret(Consumer), TokenSecret);
    rsa_sha1 ->
      BaseString = signature_base_string(HttpMethod, URL, Params),
      oauth_rsa_sha1:signature(BaseString, consumer_secret(Consumer))
  end.

-spec signature_base_string(string(), string(), [proplists:property()]) -> string(). 
signature_base_string(HttpMethod, URL, Params) ->
  NormalizedURL = oauth_uri:normalize(URL),
  NormalizedParams = normalized_params_string(Params),
  oauth_uri:calate("&", [HttpMethod, NormalizedURL, NormalizedParams]).

normalized_params_string(Params) ->
  % cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
  Encoded = [{oauth_uri:encode(K), oauth_uri:encode(V)} || {K, V} <- Params],
  Sorted = lists:sort(Encoded),
  Concatenated = [lists:concat([K, "=", V]) || {K, V} <- Sorted],
  string:join(Concatenated, "&").

-spec token_param(string(), [proplists:property()]) -> [proplists:property()].
token_param("", Params) ->
  Params;
token_param(Token, Params) ->
  [{"oauth_token", Token}|Params].

-spec token_secret_param(string(), [proplists:property()]) -> [proplists:property()].
token_secret_param("", Params) ->
  Params;
token_secret_param(Token, Params) ->
  [{"oauth_token_secret", Token}|Params].

params(Consumer, Params) ->
  Nonce = base64:encode_to_string(crypto:rand_bytes(32)), % cf. ruby-oauth
  params(Consumer, unix_timestamp(), Nonce, Params).

params(Consumer, Timestamp, Nonce, Params) ->
  [ {"oauth_version", "1.0"}
  , {"oauth_nonce", Nonce}
  , {"oauth_timestamp", integer_to_list(Timestamp)}
  , {"oauth_signature_method", signature_method_string(Consumer)}
  , {"oauth_consumer_key", consumer_key(Consumer)}
  | Params
  ].

unix_timestamp() ->
  unix_timestamp(calendar:universal_time()).

unix_timestamp(DateTime) ->
  unix_seconds(DateTime) - unix_epoch().

unix_epoch() ->
  unix_seconds({{1970,1,1},{00,00,00}}).

unix_seconds(DateTime) ->
  calendar:datetime_to_gregorian_seconds(DateTime).

signature_method_string(Consumer) ->
  case signature_method(Consumer) of
    plaintext ->
      "PLAINTEXT";
    hmac_sha1 ->
      "HMAC-SHA1";
    rsa_sha1 ->
      "RSA-SHA1"
  end.

signature_method(_Consumer={_, _, Method}) ->
  Method.

consumer_secret(_Consumer={_, Secret, _}) ->
  Secret.

consumer_key(_Consumer={Key, _, _}) ->
  Key.
