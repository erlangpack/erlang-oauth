-module(oauth_signature).

-export([value/5, base_string/3, method_to_string/1]).


value(HttpMethod, URL, Params, Consumer, TokenSecret) ->
  value(base_string(HttpMethod, URL, Params), Consumer, TokenSecret).

value(_, {_, CS, plaintext}, TS) ->
  oauth_plaintext:signature(CS, TS);
value(BaseString, {_, CS, hmac_sha1}, TS) ->
  oauth_hmac_sha1:signature(BaseString, CS, TS);
value(BaseString, {_, _, {rsa_sha1, PrivateKey}}, _) ->
  oauth_rsa_sha1:signature(BaseString, PrivateKey).

base_string(HttpMethod, URL, Params) ->
  NormalizedURL = oauth_uri:normalize(URL),
  NormalizedParams = oauth_uri:params_to_string(lists:sort(Params)),
  oauth_uri:calate("&", [HttpMethod, NormalizedURL, NormalizedParams]).

method_to_string(plaintext) ->
  "PLAINTEXT";
method_to_string(hmac_sha1) ->
  "HMAC-SHA1";
method_to_string({rsa_sha1, _}) ->
  "RSA-SHA1".
