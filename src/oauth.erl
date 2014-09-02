-module(oauth).

-export([get/3, get/5, get/6, post/3, post/5, post/6, put/6, put/7, uri/2, header/1,
  sign/6, params_decode/1, token/1, token_secret/1, verify/6]).

-export([plaintext_signature/2, hmac_sha1_signature/5,
  hmac_sha1_signature/3, rsa_sha1_signature/4, rsa_sha1_signature/2,
  signature_base_string/3, params_encode/1]).

-export([plaintext_verify/3, hmac_sha1_verify/6, hmac_sha1_verify/4,
  rsa_sha1_verify/5, rsa_sha1_verify/3]).

-export([header_params_encode/1, header_params_decode/1,
  uri_params_encode/1, uri_params_decode/1]).

-include_lib("public_key/include/public_key.hrl").

-export_type([ httpc_options/0
             , httpc_request_return/0
             , httpc_ok_result/0
             , httpc_status_line/0
             , httpc_http_version/0
             , httpc_status_code/0
             , httpc_reason_phrase/0
             , url/0
             , consumer/0
             , params/0
             , param/0
             , key/0
             , secret/0
             , method/0
             , token/0
             , token_secret/0
             ]).

% Types necessary for HTTP

% This is not exported out of httpc, I'll copy it from the documentation.
-type httpc_options()         :: [{atom(),term()}].
-type httpc_status_line()     :: { httpc_http_version(), httpc_status_code()
                                , httpc_reason_phrase()}.
-type httpc_http_version()    :: string().
-type httpc_status_code()     :: integer().
-type httpc_reason_phrase()   :: string().
-type httpc_headers()         :: [{string(), string()}].
-type httpc_request()         :: {url(), httpc_headers()} | 
                                 {url(), httpc_headers(), string(), string()}.
-type httpc_ok_result()       :: {httpc_status_line(), httpc_headers(), string()} 
                              |  {httpc_status_code(), string()}.
-type httpc_request_return()  :: {ok, httpc_ok_result()}
                              |  {error, term()}.

-type url() :: nonempty_string().

%% Types necessary for Oauth logic.
-type consumer()      :: {key(), secret(), method()}.
-type key()           :: string().       
-type secret()        :: string().
-type method()        :: 'plaintext' | 'hmac_sha1' | 'rsa_sha1'.
-type token()         :: string().
-type token_secret()  :: string().
-type params()        :: [param()].
-type param()         :: {nonempty_string(), nonempty_string()}.
 
-spec get(url(),params(),consumer()) -> httpc_request_return().
get(URL, ExtraParams, Consumer) ->
  get(URL, ExtraParams, Consumer, "", "").

-spec get(url(),params(),consumer(),token(),token_secret()) -> httpc_request_return().
get(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  get(URL, ExtraParams, Consumer, Token, TokenSecret, []).

-spec get(url(),params(),consumer(),token(),token_secret(),httpc_options()) -> httpc_request_return().
get(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = sign("GET", URL, ExtraParams, Consumer, Token, TokenSecret),
  http_request(get, {uri(URL, SignedParams), []}, HttpcOptions).

-spec post(url(),params(),consumer()) -> httpc_request_return().
post(URL, ExtraParams, Consumer) ->
  post(URL, ExtraParams, Consumer, "", "").

-spec post(url(),params(),consumer(),token(),token_secret()) -> httpc_request_return().
post(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  post(URL, ExtraParams, Consumer, Token, TokenSecret, []).

-spec post(url(),params(),consumer(),token(),token_secret(),httpc_options()) -> httpc_request_return().
post(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = sign("POST", URL, ExtraParams, Consumer, Token, TokenSecret),
  http_request(post, {URL, [], "application/x-www-form-urlencoded", uri_params_encode(SignedParams)}, HttpcOptions).

-spec put(url(),params(),{_,_},consumer(),token(),token_secret()) -> httpc_request_return().
put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret) ->
  put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret, []).

-spec put(url(),params(),{_,_},consumer(),token(),token_secret(),httpc_options()) -> httpc_request_return().
put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = sign("PUT", URL, ExtraParams, Consumer, Token, TokenSecret),
  http_request(put, {uri(URL, SignedParams), [], ContentType, Body}, HttpcOptions).

-spec uri(_,[any()]) -> any().
uri(Base, []) ->
  Base;
uri(Base, Params) ->
  lists:concat([Base, "?", uri_params_encode(Params)]).

-spec header([any()]) -> {[65 | 97 | 104 | 105 | 110 | 111 | 114 | 116 | 117 | 122,...],nonempty_string()}.
header(Params) ->
  {"Authorization", "OAuth " ++ header_params_encode(Params)}.

-spec token(params()) -> string().
token(Params) ->
  proplists:get_value("oauth_token", Params).

-spec token_secret(params()) -> string().
token_secret(Params) ->
  proplists:get_value("oauth_token_secret", Params).

-spec consumer_key(consumer()) -> key().
consumer_key(_Consumer={Key, _, _}) ->
  Key.

-spec consumer_secret(consumer()) -> secret().
consumer_secret(_Consumer={_, Secret, _}) ->
  Secret.

-spec signature_method(consumer()) -> method().
signature_method(_Consumer={_, _, Method}) ->
  Method.

-spec sign(string(),url(),_,consumer(),token(),secret()) -> nonempty_maybe_improper_list().
sign(HttpMethod, URL, Params, Consumer, Token, TokenSecret) ->
  SignatureParams = signature_params(Consumer, Params, Token),
  Signature = signature(HttpMethod, URL, SignatureParams, Consumer, TokenSecret),
  [{"oauth_signature", Signature} | SignatureParams].

-spec signature_params(consumer(),params(),token()) -> nonempty_maybe_improper_list().
signature_params(Consumer, Params, "") ->
  signature_params(Consumer, Params);
signature_params(Consumer, Params, Token) ->
  signature_params(Consumer, [{"oauth_token", Token} | Params]).

-spec signature_params(consumer(),params()) -> nonempty_maybe_improper_list().
signature_params(Consumer, Params) ->
  Timestamp = unix_timestamp(),
  Nonce = base64:encode_to_string(crypto:rand_bytes(32)), % cf. ruby-oauth
  [ {"oauth_version", "1.0"}
  , {"oauth_nonce", Nonce}
  , {"oauth_timestamp", integer_to_list(Timestamp)}
  , {"oauth_signature_method", signature_method_string(Consumer)}
  , {"oauth_consumer_key", consumer_key(Consumer)}
  | Params
  ].

-spec verify(binary() | [any()],_,url(),params(),consumer(),_) -> boolean().
verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret) ->
  case signature_method(Consumer) of
    plaintext ->
      plaintext_verify(Signature, Consumer, TokenSecret);
    hmac_sha1 ->
      hmac_sha1_verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret);
    rsa_sha1 ->
      rsa_sha1_verify(Signature, HttpMethod, URL, Params, Consumer)
  end.

-spec signature(_,_,params(),consumer(),_) -> string().
signature(HttpMethod, URL, Params, Consumer, TokenSecret) ->
  case signature_method(Consumer) of
    plaintext ->
      plaintext_signature(Consumer, TokenSecret);
    hmac_sha1 ->
      hmac_sha1_signature(HttpMethod, URL, Params, Consumer, TokenSecret);
    rsa_sha1 ->
      rsa_sha1_signature(HttpMethod, URL, Params, Consumer)
  end.

-spec signature_method_string(consumer()) -> [1..255,...].
signature_method_string(Consumer) ->
  case signature_method(Consumer) of
    plaintext ->
      "PLAINTEXT";
    hmac_sha1 ->
      "HMAC-SHA1";
    rsa_sha1 ->
      "RSA-SHA1"
  end.

-spec plaintext_signature(consumer(),_) -> string().
plaintext_signature(Consumer, TokenSecret) ->
  uri_join([consumer_secret(Consumer), TokenSecret]).

-spec plaintext_verify(binary() | [any()],consumer(),_) -> boolean().
plaintext_verify(Signature, Consumer, TokenSecret) ->
  verify_in_constant_time(Signature, plaintext_signature(Consumer, TokenSecret)).

-spec hmac_sha1_signature(_,_,params(),consumer(),_) -> [1..255].
hmac_sha1_signature(HttpMethod, URL, Params, Consumer, TokenSecret) ->
  BaseString = signature_base_string(HttpMethod, URL, Params),
  hmac_sha1_signature(BaseString, Consumer, TokenSecret).

-spec hmac_sha1_signature(binary() | maybe_improper_list(binary() | maybe_improper_list(any(),binary() | []) | byte(),binary() | []),consumer(),_) -> [1..255].
hmac_sha1_signature(BaseString, Consumer, TokenSecret) ->
  Key = uri_join([consumer_secret(Consumer), TokenSecret]),
  base64:encode_to_string(hmac_sha(Key, BaseString)).

-spec hmac_sha1_verify(binary() | [any()],_,_,params(),consumer(),_) -> boolean().
hmac_sha1_verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret) ->
  verify_in_constant_time(Signature, hmac_sha1_signature(HttpMethod, URL, Params, Consumer, TokenSecret)).

-spec hmac_sha1_verify(binary() | [any()],binary() | maybe_improper_list(binary() | maybe_improper_list(any(),binary() | []) | byte(),binary() | []),consumer(),_) -> boolean().
hmac_sha1_verify(Signature, BaseString, Consumer, TokenSecret) ->
  verify_in_constant_time(Signature, hmac_sha1_signature(BaseString, Consumer, TokenSecret)).

-spec hmac_sha([byte()],binary() | maybe_improper_list(binary() | maybe_improper_list(any(),binary() | []) | byte(),binary() | [])) -> binary().
hmac_sha(Key, Data) ->
  case erlang:function_exported(crypto, hmac, 3) of
    true ->
      crypto:hmac(sha, Key, Data);
    false ->
      crypto:sha_mac(Key, Data)
  end.

-spec rsa_sha1_signature(_,_,params(),consumer()) -> [1..255].
rsa_sha1_signature(HttpMethod, URL, Params, Consumer) ->
  BaseString = signature_base_string(HttpMethod, URL, Params),
  rsa_sha1_signature(BaseString, Consumer).

-spec rsa_sha1_signature(maybe_improper_list(binary() | maybe_improper_list(any(),binary() | []) | byte(),binary() | []),consumer()) -> [1..255].
rsa_sha1_signature(BaseString, Consumer) ->
  Key = read_private_key(consumer_secret(Consumer)),
  base64:encode_to_string(public_key:sign(list_to_binary(BaseString), sha, Key)).

-spec rsa_sha1_verify(binary() | [1..255],_,_,params(),consumer()) -> boolean().
rsa_sha1_verify(Signature, HttpMethod, URL, Params, Consumer) ->
  BaseString = signature_base_string(HttpMethod, URL, Params),
  rsa_sha1_verify(Signature, BaseString, Consumer).

-spec rsa_sha1_verify(binary() | [1..255],binary() | maybe_improper_list(binary() | maybe_improper_list(any(),binary() | []) | byte(),binary() | []),consumer()) -> boolean().
rsa_sha1_verify(Signature, BaseString, Consumer) when is_binary(BaseString) ->
  Key = read_cert_key(consumer_secret(Consumer)),
  public_key:verify(BaseString, sha, base64:decode(Signature), Key);
rsa_sha1_verify(Signature, BaseString, Consumer) when is_list(BaseString) ->
  rsa_sha1_verify(Signature, list_to_binary(BaseString), Consumer).

-spec verify_in_constant_time(binary() | [any()],string()) -> boolean().
verify_in_constant_time(<<X/binary>>, Y) when is_list(Y) ->
  verify_in_constant_time(binary_to_list(X), Y);
verify_in_constant_time(X, Y) when is_list(X) and is_list(Y) ->
  case length(X) == length(Y) of
    true ->
      verify_in_constant_time(X, Y, 0);
    false ->
      false
  end.

-spec verify_in_constant_time([integer()],string(),integer()) -> boolean().
verify_in_constant_time([X | RestX], [Y | RestY], Result) ->
  verify_in_constant_time(RestX, RestY, (X bxor Y) bor Result);
verify_in_constant_time([], [], Result) ->
  Result == 0.

-spec signature_base_string(_,_,params()) -> string().
signature_base_string(HttpMethod, URL, Params) ->
  uri_join([HttpMethod, uri_normalize(URL), params_encode(Params)]).

-spec params_encode(params()) -> string().
params_encode(Params) ->
  % cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
  Encoded = [{uri_encode(K), uri_encode(V)} || {K, V} <- Params],
  Sorted = lists:sort(Encoded),
  Concatenated = [lists:concat([K, "=", V]) || {K, V} <- Sorted],
  string:join(Concatenated, "&").

-spec params_decode(httpc_ok_result()) -> params().
params_decode(_Response={{_, _, _}, _, Body}) ->
  uri_params_decode(Body).

-type http_method() :: 'get' | 'post' | 'put'.
-spec http_request(http_method(), httpc_request(), httpc_options()) ->
                   httpc_request_return().
http_request(Method, Request, Options) ->
  httpc:request(Method, Request, [{autoredirect, false}], Options).

-define(unix_epoch, 62167219200).

-spec unix_timestamp() -> integer().
unix_timestamp() ->
  calendar:datetime_to_gregorian_seconds(calendar:universal_time()) - ?unix_epoch.

-spec read_cert_key([atom() | [any()] | char()] | #'OTPSubjectPublicKeyInfo'{} | #'OTPCertificate'{tbsCertificate::[atom() | [any()] | char()] | #'OTPSubjectPublicKeyInfo'{} | #'OTPCertificate'{tbsCertificate::[atom() | [any()] | char()] | #'OTPSubjectPublicKeyInfo'{} | #'OTPCertificate'{tbsCertificate::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}} | #'OTPTBSCertificate'{subjectPublicKeyInfo::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}}} | #'OTPTBSCertificate'{subjectPublicKeyInfo::[atom() | [any()] | char()] | #'OTPSubjectPublicKeyInfo'{} | #'OTPCertificate'{tbsCertificate::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}} | #'OTPTBSCertificate'{subjectPublicKeyInfo::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}}}} | #'OTPTBSCertificate'{subjectPublicKeyInfo::[atom() | [any()] | char()] | #'OTPSubjectPublicKeyInfo'{} | #'OTPCertificate'{tbsCertificate::[atom() | [any()] | char()] | #'OTPSubjectPublicKeyInfo'{} | #'OTPCertificate'{tbsCertificate::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}} | #'OTPTBSCertificate'{subjectPublicKeyInfo::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}}} | #'OTPTBSCertificate'{subjectPublicKeyInfo::[atom() | [any()] | char()] | #'OTPSubjectPublicKeyInfo'{} | #'OTPCertificate'{tbsCertificate::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}} | #'OTPTBSCertificate'{subjectPublicKeyInfo::[any()] | {_,_,_} | {_,_,_,_} | {_,_,_,_,_,_,_,_,_,_,_}}}}) -> any().
read_cert_key(Path) when is_list(Path) ->
  {ok, Contents} = file:read_file(Path),
  [{'Certificate', DerCert, not_encrypted}] = public_key:pem_decode(Contents),
  read_cert_key(public_key:pkix_decode_cert(DerCert, otp));
read_cert_key(#'OTPCertificate'{tbsCertificate=Cert}) ->
  read_cert_key(Cert);
read_cert_key(#'OTPTBSCertificate'{subjectPublicKeyInfo=Info}) ->
  read_cert_key(Info);
read_cert_key(#'OTPSubjectPublicKeyInfo'{subjectPublicKey=Key}) ->
  Key.

-spec read_private_key(atom() | binary() | [atom() | [any()] | char()]) -> any().
read_private_key(Path) ->
  {ok, Contents} = file:read_file(Path),
  [Info] = public_key:pem_decode(Contents),
  public_key:pem_entry_decode(Info).

-spec header_params_encode(params()) -> string().
header_params_encode(Params) ->
  intercalate(", ", [lists:concat([uri_encode(K), "=\"", uri_encode(V), "\""]) || {K, V} <- Params]).

-spec header_params_decode(binary() | maybe_improper_list(binary() | maybe_improper_list(any(),binary() | []) | char(),binary() | [])) -> [{[any()],[any()]}].
header_params_decode(String) ->
  [header_param_decode(Param) || Param <- re:split(String, ",\\s*", [{return, list}]), Param =/= ""].

-spec header_param_decode(string()) -> {[integer()],[integer()]}.
header_param_decode(Param) ->
  [Key, QuotedValue] = string:tokens(Param, "="),
  Value = string:substr(QuotedValue, 2, length(QuotedValue) - 2),
  {uri_decode(Key), uri_decode(Value)}.

-spec uri_normalize(string()) -> string() | {'error','no_scheme' | {_,atom(),_}}.
uri_normalize(URI) ->
  case http_uri:parse(URI) of
    {ok, {Scheme, UserInfo, Host, Port, Path, _Query}} -> % R15B
      uri_normalize(Scheme, UserInfo, string:to_lower(Host), Port, [Path]);
    Else ->
      Else
  end.

-spec uri_normalize(_,_,[byte()] | char(),atom() | string() | number(),[atom() | string() | number(),...]) -> string().
uri_normalize(http, UserInfo, Host, 80, Acc) ->
  uri_normalize(http, UserInfo, [Host|Acc]);
uri_normalize(https, UserInfo, Host, 443, Acc) ->
  uri_normalize(https, UserInfo, [Host|Acc]);
uri_normalize(Scheme, UserInfo, Host, Port, Acc) ->
  uri_normalize(Scheme, UserInfo, [Host, ":", Port|Acc]).

-spec uri_normalize(_, _,[atom() | string() | number(),...]) -> string().
uri_normalize(Scheme, [], Acc) ->
  lists:concat([Scheme, "://" | Acc]);
uri_normalize(Scheme, UserInfo, Acc) ->
  lists:concat([Scheme, "://", UserInfo, "@" | Acc]).

-spec uri_params_encode([{encodable(), encodable()}]) -> string().
uri_params_encode(Params) ->
  intercalate("&", [uri_join([K, V], "=") || {K, V} <- Params]).

-spec uri_params_decode(string()) -> params().
uri_params_decode(String) ->
  [uri_param_decode(Substring) || Substring <- string:tokens(String, "&")].

-spec uri_param_decode(nonempty_string()) -> param().
uri_param_decode(String) ->
  [Key, Value] = string:tokens(String, "="),
  {uri_decode(Key), uri_decode(Value)}.

-spec uri_join([encodable(),...]) -> string().
uri_join(Values) ->
  uri_join(Values, "&").

-spec uri_join([encodable(),...],nonempty_string()) -> string().
uri_join(Values, Separator) ->
  string:join(lists:map(fun uri_encode/1, Values), Separator).

-spec intercalate([T], [[T]]) -> [T].
intercalate(Sep, Xs) ->
  lists:concat(intersperse(Sep, Xs)).

-spec intersperse([T],[[T]]) -> [[T]].
intersperse(_, []) ->
  [];
intersperse(_, [X]) ->
  [X];
intersperse(Sep, [X | Xs]) ->
  [X, Sep | intersperse(Sep, Xs)].

-type encodable() :: atom() | binary() | [any()] | integer().
-spec uri_encode(encodable()) -> [any()].
uri_encode(Term) when is_integer(Term) ->
  integer_to_list(Term);
uri_encode(Term) when is_atom(Term) ->
  uri_encode(atom_to_list(Term));
uri_encode(Term) when is_binary(Term) ->
  uri_encode(binary_to_list(Term));
uri_encode(Term) when is_list(Term) ->
  uri_encode(lists:reverse(Term, []), []).

-define(is_alphanum(C), C >= $A, C =< $Z; C >= $a, C =< $z; C >= $0, C =< $9).

-spec uri_encode([any()],[any()]) -> [any()].
uri_encode([X | T], Acc) when ?is_alphanum(X); X =:= $-; X =:= $_; X =:= $.; X =:= $~ ->
  uri_encode(T, [X | Acc]);
uri_encode([X | T], Acc) ->
  NewAcc = [$%, dec2hex(X bsr 4), dec2hex(X band 16#0f) | Acc],
  uri_encode(T, NewAcc);
uri_encode([], Acc) ->
  Acc.

-spec uri_decode(string()) -> [integer()].
uri_decode(Str) when is_list(Str) ->
  uri_decode(Str, []).

-spec uri_decode(string(),[integer()]) -> [integer()].
uri_decode([$%, A, B | T], Acc) ->
  uri_decode(T, [(hex2dec(A) bsl 4) + hex2dec(B) | Acc]);
uri_decode([X | T], Acc) ->
  uri_decode(T, [X | Acc]);
uri_decode([], Acc) ->
  lists:reverse(Acc, []).

-compile({inline, [{dec2hex, 1}, {hex2dec, 1}]}).

-spec dec2hex(byte()) -> integer().
dec2hex(N) when N >= 10 andalso N =< 15 ->
  N + $A - 10;
dec2hex(N) when N >= 0 andalso N =< 9 ->
  N + $0.

-spec hex2dec(1..255) -> integer().
hex2dec(C) when C >= $A andalso C =< $F ->
  C - $A + 10;
hex2dec(C) when C >= $0 andalso C =< $9 ->
  C - $0.
