-module(oauth_rsa_sha1).

-export([signature/2]).


signature(BaseString, PrivateKeyPath) ->
  {ok, [Info]} = public_key:pem_to_der(PrivateKeyPath),
  {ok, PrivateKey} = public_key:decode_private_key(Info),
  base64:encode_to_string(public_key:sign(list_to_binary(BaseString), PrivateKey)).
