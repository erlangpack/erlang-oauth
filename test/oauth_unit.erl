-module(oauth_unit).

-include_lib("eunit/include/eunit.hrl").

-include("oauth_test_macros.hrl").


params_from_string_test_() ->
  % cf. http://oauth.net/core/1.0/#response_parameters (5.3)
  Params = oauth_params:from_string("oauth_token=ab3cd9j4ks73hf7g&oauth_token_secret=xyz4992k83j47x0b"), [
  ?_assertEqual("ab3cd9j4ks73hf7g", proplists:get_value("oauth_token", Params)),
  ?_assertEqual("xyz4992k83j47x0b", proplists:get_value("oauth_token_secret", Params))
].

params_to_header_string_test_() ->
  % cf. http://oauth.net/core/1.0/#auth_header_authorization (5.4.1)
  Params = [{oauth_consumer_key, "0685bd9184jfhq22"}, {oauth_token, "ad180jjd733klru7"}],
  String = "oauth_consumer_key=\"0685bd9184jfhq22\",oauth_token=\"ad180jjd733klru7\"", [
  ?_assertEqual(String, oauth_params:to_header_string(Params))
].

plaintext_signature_test_() -> [
  % cf. http://oauth.net/core/1.0/#rfc.section.9.4.1
  ?plaintext_signature_test("djr9rjt0jd78jf88", "jjd999tj88uiths3", "djr9rjt0jd78jf88%26jjd999tj88uiths3"),
  ?plaintext_signature_test("djr9rjt0jd78jf88", "jjd99$tj88uiths3", "djr9rjt0jd78jf88%26jjd99%2524tj88uiths3"),
  ?plaintext_signature_test("djr9rjt0jd78jf88", "", "djr9rjt0jd78jf88%26")
].

normalize_test_() -> [
  % cf. http://wiki.oauth.net/TestCases
  ?normalize_test("name=", [{name,undefined}]),
  ?normalize_test("a=b", [{a,b}]),
  ?normalize_test("a=b&c=d", [{a,b},{c,d}]),
  ?normalize_test("a=x%20y&a=x%21y", [{a,"x!y"},{a,"x y"}]),
  ?normalize_test("x=a&x%21y=a", [{"x!y",a},{x,a}])
].

base_string_test_() -> [
  % cf. http://wiki.oauth.net/TestCases
  ?base_string_test("GET", "http://example.com/", [{n,v}], ["GET&http%3A%2F%2Fexample.com%2F&n%3Dv"]),
  ?base_string_test("GET", "http://example.com", [{n,v}], ["GET&http%3A%2F%2Fexample.com%2F&n%3Dv"]),
  ?base_string_test("POST", "https://photos.example.net/request_token", [
    {oauth_version, "1.0"},
    {oauth_consumer_key, "dpf43f3p2l4k3l03"},
    {oauth_timestamp, "1191242090"},
    {oauth_nonce, "hsu94j3884jdopsl"},
    {oauth_signature_method, "PLAINTEXT"}
  ], [
    "POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth_consumer_key",
    "%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method",
    "%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0"
  ]),
  ?base_string_test("GET", "http://photos.example.net/photos", [
    {file, "vacation.jpg"},
    {size, "original"},
    {oauth_version, "1.0"},
    {oauth_consumer_key, "dpf43f3p2l4k3l03"},
    {oauth_token, "nnch734d00sl2jdk"},
    {oauth_timestamp, "1191242096"},
    {oauth_nonce, "kllo9940pd9333jh"},
    {oauth_signature_method, "HMAC-SHA1"}
  ], [
    "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26",
    "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26",
    "oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26",
    "oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
  ])
].

hmac_signature_test_() -> [
  % cf. http://wiki.oauth.net/TestCases
  ?hmac_signature_test("egQqG5AJep5sJ7anhXju1unge2I=", "cs", "", ["bs"]),
  ?hmac_signature_test("VZVjXceV7JgPq/dOTnNmEfO0Fv8=", "cs", "ts", ["bs"]),
  ?hmac_signature_test("tR3+Ty81lMeYAr/Fid0kMTYa/WM=", "kd94hf93k423kf44", "pfkkdhi9sl3r4s00", [
    "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26",
    "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26",
    "oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26",
    "oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
  ])
].
