-module(oauth_consumer).

-export([key/1, new/3, secret/1, signature_method/1]).


new(Key, Secret, SignatureMethod) ->
  {oauth_consumer, Key, Secret, SignatureMethod}.

key(Consumer) ->
  element(2, Consumer).

secret(Consumer) ->
  element(3, Consumer).

signature_method(Consumer) ->
  element(4, Consumer).
