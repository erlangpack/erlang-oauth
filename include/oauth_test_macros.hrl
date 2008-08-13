-define(plaintext_signature_test(ConsumerSecret, TokenSecret, ExpectedSignature),
  ?_assertEqual(ExpectedSignature, oauth_request:plaintext_signature(ConsumerSecret, TokenSecret))
).

-define(hmac_sha1_normalize_test(ExpectedString, Params),
  ?_assertEqual(ExpectedString, oauth_request:hmac_sha1_normalize(Params))
).

-define(hmac_sha1_base_string_test(Method, URL, Params, Expected), fun() ->
  ?assertEqual(string:join(Expected, ""), oauth_request:hmac_sha1_base_string(Method, URL, Params))
end).

-define(hmac_sha1_signature_test(ExpectedSignature, ConsumerSecret, TokenSecret, BaseString), fun() ->
  ?assertEqual(ExpectedSignature, oauth_request:hmac_sha1_signature(string:join(BaseString, []), ConsumerSecret, TokenSecret))
end).