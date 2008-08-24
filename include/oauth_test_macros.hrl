-define(plaintext_signature_test(ConsumerSecret, TokenSecret, ExpectedSignature),
  ?_assertEqual(ExpectedSignature, oauth_plaintext:signature(ConsumerSecret, TokenSecret))
).

-define(hmac_normalize_test(ExpectedString, Params),
  ?_assertEqual(ExpectedString, oauth_hmac:normalize(Params))
).

-define(hmac_base_string_test(Method, URL, Params, Expected), fun() ->
  ?assertEqual(string:join(Expected, ""), oauth_hmac:base_string(Method, URL, Params))
end).

-define(hmac_signature_test(ExpectedSignature, ConsumerSecret, TokenSecret, BaseString), fun() ->
  ?assertEqual(ExpectedSignature, oauth_hmac:signature(string:join(BaseString, []), ConsumerSecret, TokenSecret))
end).