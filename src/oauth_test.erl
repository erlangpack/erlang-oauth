-module(oauth_test).

-compile(export_all).


all() ->
  lists:all(fun(F) ->
    io:format("~s:~s~n", [?MODULE, F]),
    apply(?MODULE, F, [])
  end, [
    params_from_string,
    plaintext_signature,
    hmac_sha1_normalize,
    hmac_sha1_base_string,
    hmac_sha1_signature
  ]),
  ok.

params_from_string() ->
  % cf. http://oauth.net/core/1.0/#response_parameters (5.3)
  should_be_equal([{oauth_token, "ab3cd9j4ks73hf7g"}, {oauth_token_secret, "xyz4992k83j47x0b"}],
  oauth:params_from_string("oauth_token=ab3cd9j4ks73hf7g&oauth_token_secret=xyz4992k83j47x0b")).

plaintext_signature() ->
  % cf. http://oauth.net/core/1.0/#rfc.section.9.4.1
  ConsumerSecret="djr9rjt0jd78jf88",
  lists:all(fun({TokenSecret, Expected}) ->
    Actual = oauth_request:plaintext_signature(ConsumerSecret, TokenSecret),
    should_be_equal(Expected, Actual)
  end, [
    {"jjd999tj88uiths3","djr9rjt0jd78jf88%26jjd999tj88uiths3"},
    {"jjd99$tj88uiths3","djr9rjt0jd78jf88%26jjd99%2524tj88uiths3"},
    {"", "djr9rjt0jd78jf88%26"}
  ]).

hmac_sha1_normalize() ->
  % cf. http://wiki.oauth.net/TestCases
  lists:all(fun({Params, Expected}) ->
    should_be_equal(Expected, oauth_request:hmac_sha1_normalize(Params))
  end, [
    {[{name,undefined}], "name="},
    {[{a,b}], "a=b"},
    {[{a,b},{c,d}], "a=b&c=d"},
    {[{a,"x!y"},{a,"x y"}], "a=x%20y&a=x%21y"},
    {[{"x!y",a},{x,a}], "x=a&x%21y=a"}
  ]).

hmac_sha1_base_string() ->
  % cf. http://wiki.oauth.net/TestCases
  lists:all(fun({MethodString, URL, Params, Expected}) ->
    Actual = oauth_request:hmac_sha1_base_string(MethodString, URL, Params),
    should_be_equal(Expected, Actual)
  end, [
    {"GET", "http://example.com", [
      {n,v}
    ],
      "GET&http%3A%2F%2Fexample.com&n%3Dv"
    },
    {"POST", "https://photos.example.net/request_token", [
      {oauth_version, "1.0"},
      {oauth_consumer_key, "dpf43f3p2l4k3l03"},
      {oauth_timestamp, "1191242090"},
      {oauth_nonce, "hsu94j3884jdopsl"},
      {oauth_signature_method, "PLAINTEXT"}
    ],
      "POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_consumer_key" ++
      "%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method" ++
      "%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0"
    },
    {"GET", "http://photos.example.net/photos", [
      {file, "vacation.jpg"},
      {size, "original"},
      {oauth_version, "1.0"},
      {oauth_consumer_key, "dpf43f3p2l4k3l03"},
      {oauth_token, "nnch734d00sl2jdk"},
      {oauth_timestamp, "1191242096"},
      {oauth_nonce, "kllo9940pd9333jh"},
      {oauth_signature_method, "HMAC-SHA1"}
    ],
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" ++
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26" ++
      "oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26" ++
      "oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
    }
  ]).

hmac_sha1_signature() ->
  % cf. http://wiki.oauth.net/TestCases
  lists:all(fun({Expected, ConsumerSecret, TokenSecret, BaseString}) ->
    Actual = oauth_request:hmac_sha1_signature(BaseString, ConsumerSecret, TokenSecret),
    should_be_equal(Expected, Actual)
  end, [
    {"egQqG5AJep5sJ7anhXju1unge2I=", "cs", "", "bs"},
    {"VZVjXceV7JgPq/dOTnNmEfO0Fv8=", "cs", "ts", "bs"},
    {"tR3+Ty81lMeYAr/Fid0kMTYa/WM=", "kd94hf93k423kf44", "pfkkdhi9sl3r4s00",
      "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26" ++
      "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26" ++
      "oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26" ++
      "oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
    }
  ]).

termie() ->
  % cf. http://term.ie/oauth/example/
  Consumer = oauth_consumer:new("key", "secret", "HMAC-SHA1"),
  RequestTokenURL = "http://term.ie/oauth/example/request_token.php",
  AccessTokenURL = "http://term.ie/oauth/example/access_token.php",
  EchoURL = "http://term.ie/oauth/example/echo_api.php",
  EchoParams = [{bar, "baz"}, {method, "foo"}],
  {ok, Tokens} = tee(oauth:tokens(oauth:get(RequestTokenURL, Consumer))),  
  {ok, AccessTokens} = tee(oauth:tokens(oauth:get(AccessTokenURL, Consumer, Tokens))),
  {ok, {_,_,Data}} = tee(oauth:get(EchoURL, Consumer, AccessTokens, EchoParams)),
  should_be_equal(lists:keysort(1, EchoParams), lists:keysort(1, oauth:params_from_string(Data))).

tee(X) ->
  io:format("~p~n", [X]), X.

should_be_equal(X, X) ->
  true;
should_be_equal(X, Y) ->
  io:format("~p (expected) is not equal to ~p~n", [X, Y]),
  false.
