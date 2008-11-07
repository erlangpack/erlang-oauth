-module(oauth_request).

-export([new/3, is_signed/1, sign/3]).

-export([to_header/2, to_header/4, to_string/3, to_string/1, to_url/3, to_url/1]).


new(Method, URL, Params) ->
  {Method, URL, Params}.

is_signed(Request) ->
  proplists:is_defined(oauth_signature, params(Request)).

sign(Request, Consumer, {Token, TokenSecret}) ->
  Params = oauth_params(Request, Consumer, Token),
  Signature = signature(Params, Request, Consumer, TokenSecret),
  setelement(3, Request, [{oauth_signature, Signature}|Params]).

to_header(Realm, Request, Consumer, TokenPair) ->
  to_header(Realm, sign(Request, Consumer, TokenPair)).

to_header(Realm, SignedRequest) ->
  HeaderString = oauth_params:to_header_string(params(SignedRequest)),
  HeaderValue = fmt:sprintf("OAuth realm=\"%s\", %s", [Realm, HeaderString]),
  {"Authorization", HeaderValue}.

to_string(Request, Consumer, TokenPair) ->
  to_string(sign(Request, Consumer, TokenPair)).

to_string(SignedRequest) ->
  oauth_params:to_string(params(SignedRequest)).

to_url(Request, Consumer, TokenPair) ->
  to_url(sign(Request, Consumer, TokenPair)).

to_url(SignedRequest) ->
  fmt:sprintf("%s?%s", [url(SignedRequest), to_string(SignedRequest)]).

signature(Params, Request, Consumer, TokenSecret) ->
  ConsumerSecret = oauth_consumer:secret(Consumer),
  case oauth_consumer:signature_method(Consumer) of
    "PLAINTEXT" ->
      oauth_plaintext:signature(ConsumerSecret, TokenSecret);
    "HMAC-SHA1" ->
      BaseString = oauth_base:string(method(Request), url(Request), Params),
      oauth_hmac:signature(BaseString, ConsumerSecret, TokenSecret)
  end.

oauth_params(Request, Consumer, Token) ->
  set_consumer_key(params(Request), Consumer, Token).

set_consumer_key(Params, Consumer, Token) ->
  Param = {oauth_consumer_key, oauth_consumer:key(Consumer)},
  set_signature_method([Param|Params], Consumer, Token).

set_signature_method(Params, Consumer, Token) ->
  Method = oauth_consumer:signature_method(Consumer),
  set_token([{oauth_signature_method, Method}|Params], Token).

set_token(Params, []) ->
  set_timestamp(Params);
set_token(Params, Token) ->
  set_timestamp([{oauth_token, Token}|Params]).

set_timestamp(Params) ->
  set_nonce([{oauth_timestamp, oauth_util:unix_timestamp()}|Params]).

set_nonce(Params) ->
  set_version([{oauth_nonce, oauth_util:nonce()}|Params]).

set_version(Params) ->
  [{oauth_version, "1.0"}|Params].

method(_Request={Method, _, _}) ->
  Method.

url(_Request={_, URL, _}) ->
  URL.

params(_Request={_, _, Params}) ->
  Params.
