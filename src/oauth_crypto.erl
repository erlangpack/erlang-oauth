-module(oauth_crypto).

-export([plaintext_signature/2, hmac_signature/3, rsa_signature/2]).


plaintext_signature(ConsumerSecret, TokenSecret) ->
  Encoded = oauth_util:esprintf("%s&%s", [ConsumerSecret, TokenSecret]),
  fmt:percent_encode(Encoded).

hmac_signature(BaseString, ConsumerSecret, TokenSecret) ->
  CS = fmt:percent_encode(ConsumerSecret),
  TS = fmt:percent_encode(TokenSecret),
  Key = fmt:sprintf("%s&%s", [CS, TS]),
  base64:encode_to_string(crypto:sha_mac(Key, BaseString)).

rsa_signature(BaseString, Path) when is_list(Path) ->
  {ok, [Info]} = public_key:pem_to_der(Path),
  {ok, PrivateKey} = public_key:decode_private_key(Info),
  rsa_signature(list_to_binary(BaseString), PrivateKey);
rsa_signature(BaseString, PrivateKey) ->
  base64:encode_to_string(public_key:sign(BaseString, PrivateKey)).
