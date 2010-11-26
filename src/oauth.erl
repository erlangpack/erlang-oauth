-module(oauth).

-export([get/5, get/6, header/1, post/5, post/6, signature/5, signature_base_string/3,
  signed_params/6, token/1, token_secret/1, uri/2, verify/6]).

get(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  get(URL, ExtraParams, Consumer, Token, TokenSecret, []).

get(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = signed_params("GET", URL, ExtraParams, Consumer, Token, TokenSecret),
  oauth_http:get(uri(URL, SignedParams), HttpcOptions).

post(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  post(URL, ExtraParams, Consumer, Token, TokenSecret, []).

post(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = signed_params("POST", URL, ExtraParams, Consumer, Token, TokenSecret),
  oauth_http:post(URL, oauth_uri:params_to_string(SignedParams), HttpcOptions).

uri(Base, []) ->
  Base;
uri(Base, Params) ->
  lists:concat([Base, "?", oauth_uri:params_to_string(Params)]).

header(Params) ->
  {"Authorization", "OAuth " ++ oauth_uri:params_to_header_string(Params)}.

token(Params) ->
  proplists:get_value("oauth_token", Params).

token_secret(Params) ->
  proplists:get_value("oauth_token_secret", Params).

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

signed_params(HttpMethod, URL, ExtraParams, Consumer, Token, TokenSecret) ->
  Params = token_param(Token, params(Consumer, ExtraParams)),
  [{"oauth_signature", signature(HttpMethod, URL, Params, Consumer, TokenSecret)}|Params].

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

signature_base_string(HttpMethod, URL, Params) ->
  NormalizedURL = oauth_uri:normalize(URL),
  NormalizedParams = oauth_uri:params_to_string(lists:sort(Params)),
  oauth_uri:calate("&", [HttpMethod, NormalizedURL, NormalizedParams]).

token_param("", Params) ->
  Params;
token_param(Token, Params) ->
  [{"oauth_token", Token}|Params].

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
