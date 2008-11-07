-module(oauth_google).

-compile(export_all).

-include_lib("xmerl/include/xmerl.hrl").

% cf. http://groups.google.com/group/oauth/msg/0cf50121f946a889


test() ->
  SignatureMethod = {"RSA-SHA1", "test/rsa_private_key.pem"},
  get_request_token(oauth_consumer:new("weitu.googlepages.com", "x", SignatureMethod)).

get_request_token(Consumer) ->
  RequestTokenURL = "https://www.google.com/accounts/OAuthGetRequestToken",
  Params = [{scope, "http://www.google.com/m8/feeds"}],
  Response = oauth:get(RequestTokenURL, Consumer, Params),
  authorize_token(Consumer, tee("RequestTokenPair: ", oauth_token_pair:new(Response))).

authorize_token(Consumer, RequestTokenPair={RequestToken, _}) ->
  AuthorizeTokenURL = "https://www.google.com/accounts/OAuthAuthorizeToken",
  Params = [{oauth_token, RequestToken}],
  Prompt = fmt:sprintf("Please authorize at %s?%s~n", [AuthorizeTokenURL, oauth_params:to_string(Params)]),
  io:get_line(Prompt),
  get_access_token(Consumer, RequestTokenPair).

get_access_token(Consumer, RequestTokenPair) ->
  AccessTokenURL = "https://www.google.com/accounts/OAuthGetAccessToken",
  AccessTokenPair = tee("AccessTokenPair: ", oauth_token_pair:new(oauth:get(AccessTokenURL, Consumer, RequestTokenPair))),
  {ok, {_, _, Data}} = oauth:get("http://www.google.com/m8/feeds/contacts/default/base", Consumer, AccessTokenPair),
  {XML, _} = xmerl_scan:string(Data),
  Titles = [Node#xmlText.value || Node <- xmerl_xpath:string("//feed/entry/title/text()", XML)],
  lists:foreach(fun(Title) -> io:format("~s~n", [Title]) end, Titles).

tee(Tag, X) ->
  io:format("~s: ~p~n~n", [Tag, X]), X.
