-module(oauth_hmac).

-export([signature/3]).


signature(BaseString, ConsumerSecret, TokenSecret) ->
  CS = fmt:percent_encode(ConsumerSecret),
  TS = fmt:percent_encode(TokenSecret),
  Key = fmt:sprintf("%s&%s", [CS, TS]),
  base64:encode_to_string(crypto:sha_mac(Key, BaseString)).
