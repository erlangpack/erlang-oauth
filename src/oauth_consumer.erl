-module(oauth_consumer).

-export([key/1, new/3, secret/1, signature_method/1, signature_method_string/1]).


new(Key, Secret, SignatureMethod) ->
  {oauth_consumer, Key, Secret, SignatureMethod}.

key(Consumer) ->
  element(2, Consumer).

secret(Consumer) ->
  element(3, Consumer).

signature_method(Consumer) ->
  element(4, Consumer).

signature_method_string(Consumer) ->
  method_string(signature_method(Consumer)).

method_string({Method, _}) ->
  Method;
method_string(Method) ->
  Method.