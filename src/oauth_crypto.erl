-module(oauth_crypto).

-export([plaintext_signature/2, hmac_signature/3]).


plaintext_signature(ConsumerSecret, TokenSecret) ->
  Encoded = oauth_util:esprintf("%s&%s", [ConsumerSecret, TokenSecret]),
  fmt:percent_encode(Encoded).

hmac_signature(BaseString, ConsumerSecret, TokenSecret) ->
  CS = fmt:percent_encode(ConsumerSecret),
  TS = fmt:percent_encode(TokenSecret),
  Key = fmt:sprintf("%s&%s", [CS, TS]),
  base64:encode_to_string(crypto:sha_mac(Key, BaseString)).
