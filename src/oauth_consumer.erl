-module(oauth_consumer).

-compile(export_all).


new(Key, Secret, SignatureMethod) ->
  {oauth_consumer, Key, Secret, SignatureMethod}.

key(Consumer) ->
  element(2, Consumer).

secret(Consumer) ->
  element(3, Consumer).

signature_method(Consumer) ->
  element(4, Consumer).
