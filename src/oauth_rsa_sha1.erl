-module(oauth_rsa_sha1).

-export([signature/2, public_key/1]).

-include_lib("public_key/include/public_key.hrl").


signature(BaseString, PrivateKeyPath) ->
  {ok, [Info]} = public_key:pem_to_der(PrivateKeyPath),
  {ok, PrivateKey} = public_key:decode_private_key(Info),
  base64:encode_to_string(public_key:sign(list_to_binary(BaseString), PrivateKey)).

public_key(Path) when is_list(Path) ->
  {ok, [{cert, DerCert, not_encrypted}]} = public_key:pem_to_der(Path),
  {ok, Cert} = pubkey_cert_records:decode_cert(DerCert, otp),
  public_key(Cert);
public_key(#'OTPCertificate'{tbsCertificate=Cert}) ->
  public_key(Cert);
public_key(#'OTPTBSCertificate'{subjectPublicKeyInfo=Info}) ->
  public_key(Info);
public_key(#'OTPSubjectPublicKeyInfo'{subjectPublicKey=Key}) ->
  Key.
