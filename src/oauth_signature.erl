-module(oauth_signature).

-export([new/5]).


new(RequestMethod, URL, Params, ConsumerSecret, TokenSecret) when is_list(ConsumerSecret) ->
  new(method(Params), RequestMethod, URL, Params, ConsumerSecret, TokenSecret);
new(RequestMethod, URL, Params, Consumer, TokenSecret) ->
  new(RequestMethod, URL, Params, oauth_consumer:secret(Consumer), TokenSecret).

new("PLAINTEXT", _RequestMethod, _URL, _Params, ConsumerSecret, TokenSecret) ->
  oauth_plaintext:signature(ConsumerSecret, TokenSecret);
new("HMAC-SHA1", RequestMethod, URL, Params, ConsumerSecret, TokenSecret) ->
  oauth_hmac:signature({RequestMethod, URL, Params}, ConsumerSecret, TokenSecret).

method(Params) ->
  proplists:get_value(oauth_signature_method, Params).
