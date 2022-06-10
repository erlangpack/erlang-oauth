% Copyright (c) 2008-2021 Tim Fletcher
%
% Permission is hereby granted, free of charge, to any person obtaining
% a copy of this software and associated documentation files (the
% "Software"), to deal in the Software without restriction, including
% without limitation the rights to use, copy, modify, merge, publish,
% distribute, sublicense, and/or sell copies of the Software, and to
% permit persons to whom the Software is furnished to do so, subject to
% the following conditions:
%
% The above copyright notice and this permission notice shall be
% included in all copies or substantial portions of the Software.
%
% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
% EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
% MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
% NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
% LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
% OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
% WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-module(oauth).

-export([get/3, get/5, get/6, post/3, post/5, post/6, delete/3, delete/5, delete/6, put/6, put/7]).

-export([uri/2, header/1, sign/6, params_decode/1, token/1, token_secret/1, verify/6]).

-export([plaintext_signature/2, hmac_sha1_signature/5,
  hmac_sha1_signature/3, rsa_sha1_signature/4, rsa_sha1_signature/2,
  signature_base_string/3, params_encode/1, signature/5]).

-export([plaintext_verify/3, hmac_sha1_verify/6, hmac_sha1_verify/4,
  rsa_sha1_verify/5, rsa_sha1_verify/3]).

-export([header_params_encode/1, header_params_decode/1]).

-include_lib("public_key/include/public_key.hrl").

-type signature_method() :: plaintext | hmac_sha1 | rsa_sha1.
%% <ul>
%%  <li>`PLAINTEXT' is a simple method for a more efficient implementation which offloads 
%% most of the security requirements to the HTTPS layer.</li>
%% <li>`HMAC-SHA1' offers a simple and common algorithm that is available on most platforms 
%% but not on all legacy devices and uses a symmetric shared secret.</li>
%% <li>`RSA-SHA1' provides enhanced security using key-pairs but is more complex and 
%% requires key generation and a longer learning curve.</li>
%% </ul>
-export_type([
	signature_method/0
]).

-if(?OTP_RELEASE >= 22).
-define(HMAC_SHA1(Key, Data), crypto:mac(hmac, sha, Key, Data)).
-else.
-define(HMAC_SHA1(Key, Data), crypto:hmac(sha, Key, Data)).
-endif.

%% @doc Send request using HTTP-method GET. `Token' and `TokenSecret' values are empty string.
%% @param URL server URL
%% @param ExtraParams signature params
%% @param Consumer client information
%% @equiv get(URL, ExtraParams, Consumer, "", "")

-spec get(URL, ExtraParams, Consumer) -> Result when
	URL :: httpc:url(), 
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
get(URL, ExtraParams, Consumer) ->
  get(URL, ExtraParams, Consumer, "", "").

%% @doc Send request using HTTP-method GET.
%% @param URL server URL
%% @param ExtraParams signature params
%% @param Consumer client information
%% @param Token sign token
%% @param TokenSecret sign token secret
%% @equiv get(URL, ExtraParams, Consumer, Token, TokenSecret, [])

-spec get(URL, ExtraParams, Consumer, Token, TokenSecret) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
get(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  get(URL, ExtraParams, Consumer, Token, TokenSecret, []).

%% @doc Send request using HTTP-method GET.
%% @param URL server URL
%% @param ExtraParams signature params
%% @param Consumer client information
%% @param Token sign token
%% @param TokenSecret sign token secret
%% @param HttpcOptions HTTP options

-spec get(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	HttpcOptions :: [Option],
	Option :: {sync, boolean()} | {stream, StreamTo} | {body_format, BodyFormat} |
				{full_result, boolean()} | {headers_as_is, boolean()} | {socket_opts, SocketOpts} | 
				{receiver, Receiver},
	StreamTo :: none | self | {self, once} | httpc:filename(),
	BodyFormat :: 'string' | 'binary',
	SocketOpts :: [httpc:socket_opt()],
	Receiver :: Receiver :: pid() | function() | {Module, Function, Args},
	Module :: atom(),
	Function :: atom(),
	Args :: list(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
get(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = sign("GET", URL, ExtraParams, Consumer, Token, TokenSecret),
  http_request(get, {uri(URL, SignedParams), []}, HttpcOptions).

%% @doc Send request using HTTP-method POST.
%% @equiv post(URL, ExtraParams, Consumer, "", "")

-spec post(URL, ExtraParams, Consumer) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
post(URL, ExtraParams, Consumer) ->
  post(URL, ExtraParams, Consumer, "", "").

%% @doc Send request using HTTP-method POST.
%% @equiv post(URL, ExtraParams, Consumer, Token, TokenSecret, [])

-spec post(URL, ExtraParams, Consumer, Token, TokenSecret) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
post(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  post(URL, ExtraParams, Consumer, Token, TokenSecret, []).

%% @doc Send request using HTTP-method POST.

-spec post(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	HttpcOptions :: [Option],
	Option :: {sync, boolean()} | {stream, StreamTo} | {body_format, BodyFormat} |
				{full_result, boolean()} | {headers_as_is, boolean()} | {socket_opts, SocketOpts} | 
				{receiver, Receiver},
	StreamTo :: none | self | {self, once} | httpc:filename(),
	BodyFormat :: 'string' | 'binary',
	SocketOpts :: [httpc:socket_opt()],
	Receiver :: Receiver :: pid() | function() | {Module, Function, Args},
	Module :: atom(),
	Function :: atom(),
	Args :: list(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
post(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = sign("POST", URL, ExtraParams, Consumer, Token, TokenSecret),
  http_request(post, {URL, [], "application/x-www-form-urlencoded", uri_string:compose_query(SignedParams)}, HttpcOptions).

%% @doc Send request using HTTP-method DELETE.
%% @equiv delete(URL, ExtraParams, Consumer, "", "")

-spec delete(URL, ExtraParams, Consumer) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
delete(URL, ExtraParams, Consumer) ->
  delete(URL, ExtraParams, Consumer, "", "").

%% @doc Send request using HTTP-method DELETE.
%% @equiv delete(URL, ExtraParams, Consumer, Token, TokenSecret, [])

-spec delete(URL, ExtraParams, Consumer, Token, TokenSecret) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
delete(URL, ExtraParams, Consumer, Token, TokenSecret) ->
  delete(URL, ExtraParams, Consumer, Token, TokenSecret, []).

%% @doc Send request using HTTP-method DELETE.

-spec delete(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	HttpcOptions :: [Option],
	Option :: {sync, boolean()} | {stream, StreamTo} | {body_format, BodyFormat} |
				{full_result, boolean()} | {headers_as_is, boolean()} | {socket_opts, SocketOpts} | 
				{receiver, Receiver},
	StreamTo :: none | self | {self, once} | httpc:filename(),
	BodyFormat :: 'string' | 'binary',
	SocketOpts :: [httpc:socket_opt()],
	Receiver :: Receiver :: pid() | function() | {Module, Function, Args},
	Module :: atom(),
	Function :: atom(),
	Args :: list(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
delete(URL, ExtraParams, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = sign("DELETE", URL, ExtraParams, Consumer, Token, TokenSecret),
  http_request(delete, {URL, [], "application/x-www-form-urlencoded", uri_string:compose_query(SignedParams)}, HttpcOptions).

%% @doc Send request using HTTP-method PUT.
%% @equiv put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret, [])

-spec put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	ContentType :: httpc:content_type(), 
	Body :: httpc:body(),
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret) ->
  put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret, []).

%% @doc Send request using HTTP-method PUT.

-spec put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret, HttpcOptions) -> Result when
	URL :: httpc:url(),
	ExtraParams :: list(), 
	ContentType :: httpc:content_type(), 
	Body :: httpc:body(),
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(), 
	TokenSecret :: string(),
	HttpcOptions :: [Option],
	Option :: {sync, boolean()} | {stream, StreamTo} | {body_format, BodyFormat} |
				{full_result, boolean()} | {headers_as_is, boolean()} | {socket_opts, SocketOpts} | 
				{receiver, Receiver},
	StreamTo :: none | self | {self, once} | httpc:filename(),
	BodyFormat :: 'string' | 'binary',
	SocketOpts :: [httpc:socket_opt()],
	Receiver :: Receiver :: pid() | function() | {Module, Function, Args},
	Module :: atom(),
	Function :: atom(),
	Args :: list(),
	Result :: {ok, RequestTokenResponse} | {ok, saved_to_file} | {error, Reason},
	RequestTokenResponse :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
put(URL, ExtraParams, {ContentType, Body}, Consumer, Token, TokenSecret, HttpcOptions) ->
  SignedParams = sign("PUT", URL, ExtraParams, Consumer, Token, TokenSecret),
  http_request(put, {uri(URL, SignedParams), [], ContentType, Body}, HttpcOptions).

%% @doc Build URI using provided parameters.
-spec uri(Base, Params) -> Result when
	Base :: string(), 
	Params :: QueryList,
	QueryList :: [{unicode:chardata(), unicode:chardata() | true}],
	Result :: string().
uri(Base, []) ->
  Base;
uri(Base, Params) ->
  lists:concat([Base, "?", uri_string:compose_query(Params)]).

%% @doc Get encode authorization paramaters.
%% @returns {"Authorization", "OAuth " ++ string()}

-spec header(Params) -> Result when
	Params :: [{Key, Value}],
	Key :: Term, 
	Value :: Term,
	Term :: integer() | atom() | binary() | list(),
	Result :: {string(), string()}.
header(Params) ->
  {"Authorization", "OAuth " ++ header_params_encode(Params)}.

%% @doc Get `oauth_token'.

-spec token(Params) -> Result when
	Params :: [term()],
	Result :: string().
token(Params) ->
  proplists:get_value("oauth_token", Params).

%% @doc Get `oauth_token_secret'.

-spec token_secret(Params) -> Result when
	Params :: [term()],
	Result :: string().
token_secret(Params) ->
  proplists:get_value("oauth_token_secret", Params).

-spec consumer_key(Consumer) -> Result when
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: Key.
consumer_key(_Consumer={Key, _, _}) ->
  Key.

-spec consumer_secret(Consumer) -> Result when
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: Secret.
consumer_secret(_Consumer={_, Secret, _}) ->
  Secret.

-spec signature_method(Consumer) -> Result when
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: Method.
signature_method(_Consumer={_, _, Method}) ->
  Method.

%% @doc Get signature parameters.
%% @param HttpMethod "GET" | "POST" | "DELETE" | "PUT"

-spec sign(HttpMethod, URL, Params, Consumer, Token, TokenSecret) -> Result when
	HttpMethod :: string(),
	URL :: httpc:url(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Token :: string(),
	TokenSecret :: string(),
	Result :: [{string(),string()}].
sign(HttpMethod, URL, Params, Consumer, Token, TokenSecret) ->
  SignatureParams = signature_params(Consumer, Params, Token),
  Signature = signature(HttpMethod, URL, SignatureParams, Consumer, TokenSecret),
  [{"oauth_signature", Signature} | SignatureParams].

-spec signature_params(Consumer, Params, Token) -> Result when
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Term :: integer() | atom() | binary() | list(),
	Token :: string(),
	Result :: [{string(), string()}].
signature_params(Consumer, Params, "") ->
  signature_params(Consumer, Params);
signature_params(Consumer, Params, Token) ->
  signature_params(Consumer, [{"oauth_token", Token} | Params]).

signature_params(Consumer, Params) ->
  Timestamp = unix_timestamp(),
  Nonce = base64:encode_to_string(crypto:strong_rand_bytes(32)), % cf. ruby-oauth
  [ {"oauth_version", "1.0"}
  , {"oauth_nonce", Nonce}
  , {"oauth_timestamp", integer_to_list(Timestamp)}
  , {"oauth_signature_method", signature_method_string(Consumer)}
  , {"oauth_consumer_key", consumer_key(Consumer)}
  | Params
  ].

%% @doc Verify signature by provided signature method.
-spec verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret) -> Result when
	Signature :: base64:base64_string() | base64:base64_binary(),
	HttpMethod :: string(), 
	URL :: httpc:url(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Term :: integer() | atom() | binary() | list(),
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: boolean().
verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret) ->
  case signature_method(Consumer) of
    plaintext ->
      plaintext_verify(Signature, Consumer, TokenSecret);
    hmac_sha1 ->
      hmac_sha1_verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret);
    rsa_sha1 ->
      rsa_sha1_verify(Signature, HttpMethod, URL, Params, Consumer)
  end.

%% @doc Get signature using provided signature method.
-spec signature(HttpMethod, URL, Params, Consumer, TokenSecret) -> Result when
	HttpMethod :: string(), 
	URL :: httpc:url(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Term :: integer() | atom() | binary() | list(),
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: base64:base64_string().
signature(HttpMethod, URL, Params, Consumer, TokenSecret) ->
  case signature_method(Consumer) of
    plaintext ->
      plaintext_signature(Consumer, TokenSecret);
    hmac_sha1 ->
      hmac_sha1_signature(HttpMethod, URL, Params, Consumer, TokenSecret);
    rsa_sha1 ->
      rsa_sha1_signature(HttpMethod, URL, Params, Consumer)
  end.

%% @doc Get selected signature method.
%% @returns "PLAINTEXT" | "HMAC-SHA1" | "RSA-SHA1"

-spec signature_method_string(Consumer) -> Result when
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: string().
signature_method_string(Consumer) ->
  case signature_method(Consumer) of
    plaintext ->
      "PLAINTEXT";
    hmac_sha1 ->
      "HMAC-SHA1";
    rsa_sha1 ->
      "RSA-SHA1"
  end.

%% @doc Build plain text Signature

-spec plaintext_signature(Consumer, TokenSecret) -> Result when
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: base64:base64_string().
plaintext_signature(Consumer, TokenSecret) ->
  uri_join([consumer_secret(Consumer), TokenSecret]).

%% @doc Verify plain text Signature

-spec plaintext_verify(Signature, Consumer, TokenSecret) -> Result when
	Signature :: base64:base64_string() | base64:base64_binary(),
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: boolean().
plaintext_verify(Signature, Consumer, TokenSecret) ->
  verify_in_constant_time(Signature, plaintext_signature(Consumer, TokenSecret)).

%% @doc Build HMAC-SHA1 Signature

-spec hmac_sha1_signature(HttpMethod, URL, Params, Consumer, TokenSecret) -> Result when
	HttpMethod :: string(),
	URL :: httpc:url(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: base64:base64_string().
hmac_sha1_signature(HttpMethod, URL, Params, Consumer, TokenSecret) ->
  BaseString = signature_base_string(HttpMethod, URL, Params),
  hmac_sha1_signature(BaseString, Consumer, TokenSecret).

%% @doc Build HMAC-SHA1 Signature

-spec hmac_sha1_signature(BaseString, Consumer, TokenSecret) -> Result when
	BaseString :: string() | binary(),
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: base64:base64_string().
hmac_sha1_signature(BaseString, Consumer, TokenSecret) ->
  Key = uri_join([consumer_secret(Consumer), TokenSecret]),
  base64:encode_to_string(?HMAC_SHA1(Key, BaseString)).

%% @doc Verify HMAC-SHA1 Signature

-spec hmac_sha1_verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret) -> Result when
	Signature :: base64:base64_string() | base64:base64_binary(),
	HttpMethod :: string(), 
	URL :: httpc:url(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: boolean().
hmac_sha1_verify(Signature, HttpMethod, URL, Params, Consumer, TokenSecret) ->
  verify_in_constant_time(Signature, hmac_sha1_signature(HttpMethod, URL, Params, Consumer, TokenSecret)).

%% @doc Verify HMAC-SHA1 Signature

-spec hmac_sha1_verify(Signature, BaseString, Consumer, TokenSecret) -> Result when
	Signature :: base64:base64_string() | base64:base64_binary(),
	BaseString :: string() | binary(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	TokenSecret :: string(),
	Result :: boolean().
hmac_sha1_verify(Signature, BaseString, Consumer, TokenSecret) ->
  verify_in_constant_time(Signature, hmac_sha1_signature(BaseString, Consumer, TokenSecret)).

%%@doc Build RSA_SHA1 Signature

-spec rsa_sha1_signature(HttpMethod, URL, Params, Consumer) -> Result when
	HttpMethod :: string(),
	URL :: httpc:url(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: base64:base64_string().
rsa_sha1_signature(HttpMethod, URL, Params, Consumer) ->
  BaseString = signature_base_string(HttpMethod, URL, Params),
  rsa_sha1_signature(BaseString, Consumer).

%%@doc Build RSA_SHA1 Signature

-spec rsa_sha1_signature(BaseString, Consumer) -> Result when
	BaseString :: string() | binary(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(),
	Result :: base64:base64_string().
rsa_sha1_signature(BaseString, Consumer) ->
  Key = read_private_key(consumer_secret(Consumer)),
  base64:encode_to_string(public_key:sign(list_to_binary(BaseString), sha, Key)).

%%@doc Verify RSA_SHA1 Signature

-spec rsa_sha1_verify(Signature, HttpMethod, URL, Params, Consumer) -> Result when
	Signature :: base64:base64_string() | base64:base64_binary(),
	HttpMethod :: string(),
	URL :: httpc:url(),
	Params :: [{ParamsKey, ParamsValue}],
	ParamsKey :: Term, 
	ParamsValue :: Term,
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(), 
	Result :: boolean().
rsa_sha1_verify(Signature, HttpMethod, URL, Params, Consumer) ->
  BaseString = signature_base_string(HttpMethod, URL, Params),
  rsa_sha1_verify(Signature, BaseString, Consumer).

%%@doc Verify RSA_SHA1 Signature

-spec rsa_sha1_verify(Signature, BaseString, Consumer) -> Result when
	Signature :: base64:base64_string() | base64:base64_binary(), 
	BaseString :: string() | binary(), 
	Consumer :: {Key, Secret, Method},
	Key :: string(), 
	Secret :: string(), 
	Method :: signature_method(), 
	Result :: boolean().
rsa_sha1_verify(Signature, BaseString, Consumer) when is_binary(BaseString) ->
  Key = read_cert_key(consumer_secret(Consumer)),
  public_key:verify(BaseString, sha, base64:decode(Signature), Key);
rsa_sha1_verify(Signature, BaseString, Consumer) when is_list(BaseString) ->
  rsa_sha1_verify(Signature, list_to_binary(BaseString), Consumer).

-spec verify_in_constant_time(X,Y) -> Result when
	X :: list(),
	Y :: list(),
	Result :: boolean().
verify_in_constant_time(X, Y) when is_list(X) and is_list(Y) ->
  case length(X) == length(Y) of
    true ->
      verify_in_constant_time(X, Y, 0);
    false ->
      false
  end.

-spec verify_in_constant_time(X, Y, Result) -> FunResult when
	X :: list(),
	Y :: list(),
	Result :: integer(),
	FunResult :: boolean().
verify_in_constant_time([X | RestX], [Y | RestY], Result) ->
  verify_in_constant_time(RestX, RestY, (X bxor Y) bor Result);
verify_in_constant_time([], [], Result) ->
  Result == 0.

%% @doc Build signature string.
-spec signature_base_string(HttpMethod, URL, Params) -> Result when
	HttpMethod :: string(), 
	URL  :: uri_string:uri_string(), 
	Params :: list(),
	Result :: uri_string:uri_string().
signature_base_string(HttpMethod, URL, Params) ->
  uri_join([HttpMethod, base_string_uri(URL), params_encode(Params)]).

%%@doc Encode provided parameters.

-spec params_encode(Params) -> Result when
	Params :: [{Key, Value}],
	Key :: Term,
	Value :: Term,
	Term :: integer() | atom() | binary() | list(),
	Result :: string().
params_encode(Params) ->
  % cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
  Encoded = [{uri_encode(K), uri_encode(V)} || {K, V} <- Params],
  Sorted = lists:sort(Encoded),
  Concatenated = [lists:concat([K, "=", V]) || {K, V} <- Sorted],
  string:join(Concatenated, "&").

%%@doc Decode provided parameters from query string.

-spec params_decode(Response) -> Result when
	Response :: {{term(), term(), term()}, term(), Body},
	Body :: QueryString,
	QueryString :: uri_string:uri_string(),
	Result :: QueryList,
	QueryList :: [{unicode:chardata(), unicode:chardata() | true}] | uri_string:error().
params_decode(_Response={{_, _, _}, _, Body}) ->
  uri_string:dissect_query(Body).

-spec http_request(Method, Request, Options) -> Result when
	Method :: httpc:method(),
	Request :: httpc:request(), 
	Options :: [Option],
	Option :: {sync, boolean()} | {stream, StreamTo} | {body_format, BodyFormat} |
				{full_result, boolean()} | {headers_as_is, boolean()} | {socket_opts, SocketOpts} | 
				{receiver, Receiver},
	StreamTo :: none | self | {self, once} | httpc:filename(),
	BodyFormat :: 'string' | 'binary',
	SocketOpts :: [httpc:socket_opt()],
	Receiver :: Receiver :: pid() | function() | {Module, Function, Args},
	Module :: atom(),
	Function :: atom(),
	Args :: list(),
	Result :: {ok, OkResult} | {ok, saved_to_file} | {error, Reason},
	OkResult :: {httpc:status_line(), httpc:headers(), Body} | {httpc:status_code(), Body} | httpc:request_id(),
	Body :: httpc:http_string() | binary(),
	Reason :: term().
http_request(Method, Request, Options) ->
  httpc:request(Method, Request, [{autoredirect, false}], Options).

-define(unix_epoch, 62167219200).

-spec unix_timestamp() -> Result when
	Result :: non_neg_integer().
unix_timestamp() ->
  calendar:datetime_to_gregorian_seconds(calendar:universal_time()) - ?unix_epoch.

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

-spec read_private_key(Path) -> Result when
	Path :: file:name_all(),
	Result :: term().
read_private_key(Path) ->
  {ok, Contents} = file:read_file(Path),
  [Info] = public_key:pem_decode(Contents),
  public_key:pem_entry_decode(Info).

%% @doc Encode authorization paramaters list as a string.
%% @returns Encoded authorization paramaters list as a string.
-spec header_params_encode(Params) -> Result when
	Params :: [{Key, Value}],
	Key :: Term, 
	Value :: Term,
	Term :: integer() | atom() | binary() | list(),
	Result :: string().
header_params_encode(Params) ->
  intercalate(", ", [lists:concat([uri_encode(K), "=\"", uri_encode(V), "\""]) || {K, V} <- Params]).

%% @doc Dencode authorization paramaters list.
%% @returns Dencoded authorization paramaters list.
-spec header_params_decode(String) -> Result when
	String :: string(),
	Result :: [Param],
	Param :: {Key, Value},
	Key :: string(),
	Value :: string().
header_params_decode(String) ->
  [header_param_decode(Param) || Param <- re:split(String, ",\\s*", [{return, list}]), Param =/= ""].

-spec header_param_decode(Param) -> Result when
	Param :: SeparatorList,
	SeparatorList :: string(),
	Result :: {Key, Value},
	Key :: string(),
	Value :: string().
header_param_decode(Param) ->
  [Key, QuotedValue] = string:tokens(Param, "="),
  Value = string:substr(QuotedValue, 2, length(QuotedValue) - 2),
  {uri_decode(Key), uri_decode(Value)}.

-spec base_string_uri(Str) -> Result when
	Str :: URIString,
	URIString :: uri_string:uri_string(),
	Result :: URIString,
	URIString :: uri_string:uri_string() | uri_string:error().
base_string_uri(Str) ->
  % https://tools.ietf.org/html/rfc5849#section-3.4.1.2
  Map1 = uri_string:parse(Str),
  Scheme = string:to_lower(maps:get(scheme, Map1)),
  Host = string:to_lower(maps:get(host, Map1)),
  Map2 = maps:put(scheme, Scheme, Map1),
  Map3 = maps:put(host, Host, Map2),
  Map4 = maps:remove(query, Map3),
  Map5 = without_default_port(Scheme, Map4),
  uri_string:recompose(Map5).

without_default_port("http", #{ port := 80 } = Map) ->
  maps:remove(port, Map);
without_default_port("https", #{ port := 443 } = Map) ->
  maps:remove(port, Map);
without_default_port(_Scheme, Map) ->
  Map.

%% @equiv uri_join(Values, "&")

-spec uri_join(Values) -> Result when
	Values :: list(integer() | atom() | binary() | list()),
	Result :: string().
uri_join(Values) ->
  uri_join(Values, "&").

-spec uri_join(Values, Separator) -> Result when
	Values :: list(integer() | atom() | binary() | list()),
	Separator :: string(),
	Result :: string().
uri_join(Values, Separator) ->
  string:join(lists:map(fun uri_encode/1, Values), Separator).

intercalate(Sep, Xs) ->
  lists:concat(intersperse(Sep, Xs)).

intersperse(_, []) ->
  [];
intersperse(_, [X]) ->
  [X];
intersperse(Sep, [X | Xs]) ->
  [X, Sep | intersperse(Sep, Xs)].

-spec uri_encode(Term) -> Result when
	Term :: integer() | atom() | binary() | list(),
	Result :: string().
uri_encode(Term) when is_integer(Term) ->
  integer_to_list(Term);
uri_encode(Term) when is_atom(Term) ->
  uri_encode(atom_to_list(Term));
uri_encode(Term) when is_binary(Term) ->
  uri_encode(binary_to_list(Term));
uri_encode(Term) when is_list(Term) ->
  uri_encode(lists:reverse(Term, []), []).

-define(is_alphanum(C), C >= $A, C =< $Z; C >= $a, C =< $z; C >= $0, C =< $9).

-spec uri_encode(Term, Acc) -> Result when
	Term :: string(),
	Acc :: list(),
	Result :: string().
uri_encode([X | T], Acc) when ?is_alphanum(X); X =:= $-; X =:= $_; X =:= $.; X =:= $~ ->
  uri_encode(T, [X | Acc]);
uri_encode([X | T], Acc) ->
  NewAcc = [$%, dec2hex(X bsr 4), dec2hex(X band 16#0f) | Acc],
  uri_encode(T, NewAcc);
uri_encode([], Acc) ->
  Acc.

%% @equiv uri_decode(Str, [])

-spec uri_decode(Str) -> Result when
	Str :: string(),
	Result :: string().
uri_decode(Str) when is_list(Str) ->
  uri_decode(Str, []).

uri_decode([$%, A, B | T], Acc) ->
  uri_decode(T, [(hex2dec(A) bsl 4) + hex2dec(B) | Acc]);
uri_decode([X | T], Acc) ->
  uri_decode(T, [X | Acc]);
uri_decode([], Acc) ->
  lists:reverse(Acc, []).

-compile({inline, [{dec2hex, 1}, {hex2dec, 1}]}).

dec2hex(N) when N >= 10 andalso N =< 15 ->
  N + $A - 10;
dec2hex(N) when N >= 0 andalso N =< 9 ->
  N + $0.

hex2dec(C) when C >= $A andalso C =< $F ->
  C - $A + 10;
hex2dec(C) when C >= $0 andalso C =< $9 ->
  C - $0.
