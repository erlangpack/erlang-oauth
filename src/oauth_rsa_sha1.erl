-module(oauth_rsa_sha1).

-export([signature/2, verify/3]).

-include_lib("public_key/include/public_key.hrl").

-spec signature(string(), string()) -> string().
signature(BaseString, PrivateKeyPath) ->
  {ok, Contents} = file:read_file(PrivateKeyPath),
  [Info] = public_key:pem_decode(Contents),
  PrivateKey = public_key:pem_entry_decode(Info),
  base64:encode_to_string(public_key:sign(list_to_binary(BaseString), sha, PrivateKey)).

-spec verify(string(), string(), term()) -> boolean().
verify(Signature, BaseString, Cert) ->
  public_key:verify(to_binary(BaseString), sha, base64:decode(Signature), pkey(Cert)).

to_binary(Term) when is_list(Term) ->
  list_to_binary(Term);
to_binary(Term) when is_binary(Term) ->
  Term.

pkey(Path) when is_list(Path) ->
  {ok, Contents} = file:read_file(Path),
  [{'Certificate', DerCert, not_encrypted}] = public_key:pem_decode(Contents),
  pkey(public_key:pkix_decode_cert(DerCert, otp));
pkey(#'OTPCertificate'{tbsCertificate=Cert}) ->
  pkey(Cert);
pkey(#'OTPTBSCertificate'{subjectPublicKeyInfo=Info}) ->
  pkey(Info);
pkey(#'OTPSubjectPublicKeyInfo'{subjectPublicKey=Key}) ->
  Key.
