-define(plaintext_signature_test(ConsumerSecret, TokenSecret, ExpectedSignature),
  ?_assertEqual(ExpectedSignature, oauth_plaintext:signature(ConsumerSecret, TokenSecret))
).

-define(normalize_test(ExpectedString, Params),
  ?_assertEqual(ExpectedString, oauth_base:normalize(Params))
).

-define(base_string_test(Method, URL, Params, Expected), fun() ->
  ?assertEqual(string:join(Expected, ""), oauth_base:string(Method, URL, Params))
end).

-define(hmac_signature_test(ExpectedSignature, ConsumerSecret, TokenSecret, BaseString), fun() ->
  ?assertEqual(ExpectedSignature, oauth_hmac:signature(string:join(BaseString, []), ConsumerSecret, TokenSecret))
end).