-ifndef(_OAUTH_INCLUDED).
-define(_OAUTH_INCLUDED, true).

-type oauth_method() :: plaintext | hmac_sha1 | rsa_sha1.

-record(oauth_consumer, {
  key       :: string(),
  secret    :: string(),
  method    :: oauth_method()
}).

-endif.   % _OAUTH_INCLUDED
