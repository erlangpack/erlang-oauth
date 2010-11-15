-module(oauth_client).

-behaviour(gen_server).

-export([access_token_params/1, request_token_params/1,
         deauthorize/1, get/2, get/3, get/4, get_access_token/2,
         get_access_token/3, get_access_token/4, get_request_token/2, get_request_token/3,
         get_request_token/4, start/1, start/2, start_link/1, start_link/2, stop/1]).
-export([oauth_get/6]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

-type consumer() :: tuple().
-type state() :: {consumer()} | {consumer(), [proplists:property()]} | {consumer(), [proplists:property()], [proplists:property()]}.

-export_type([consumer/0]).

%%============================================================================
%% API functions
%%============================================================================
-spec start(consumer()) -> {ok, pid()}.
start(Consumer) ->
  gen_server:start(?MODULE, Consumer, []).

-spec start({local | global, atom()}, consumer()) -> {ok, pid()}.
start(ServerName, Consumer) ->
  gen_server:start(ServerName, ?MODULE, Consumer, []).

-spec start_link(consumer()) -> {ok, pid()}.
start_link(Consumer) ->
  gen_server:start_link(?MODULE, Consumer, []).

-spec start_link({local | global, atom()}, consumer()) -> {ok, pid()}.
start_link(ServerName, Consumer) ->
  gen_server:start_link(ServerName, ?MODULE, Consumer, []).

-spec get_request_token(pid(), string()) -> string(). 
get_request_token(Client, URL) ->
  get_request_token(Client, URL, [], header).

-spec get_request_token(pid(), string(), [{string(), string()}]) -> string(). 
get_request_token(Client, URL, Params) ->
  gen_server:call(Client, {get_request_token, URL, Params, header}).

-spec get_request_token(pid(), string(), [{string(), string()}], header | querystring) -> string(). 
get_request_token(Client, URL, Params, ParamsMethod) ->
  gen_server:call(Client, {get_request_token, URL, Params, ParamsMethod}).

-spec get_access_token(pid(), string()) -> ok | term().
get_access_token(Client, URL) ->
  get_access_token(Client, URL, [], header).

-spec get_access_token(pid(), string(), [proplists:property()]) -> ok | term().
get_access_token(Client, URL, Params) ->
  gen_server:call(Client, {get_access_token, URL, Params, header}).

-spec get_access_token(pid(), string(), [proplists:property()], header | querystring) -> ok | term().
get_access_token(Client, URL, Params, ParamsMethod) ->
  gen_server:call(Client, {get_access_token, URL, Params, ParamsMethod}).

-spec get(pid(), string()) -> ok | term().
get(Client, URL) ->
  get(Client, URL, [], header).

-spec get(pid(), string(), [proplists:property()]) -> ok | term().
get(Client, URL, Params) ->
  gen_server:call(Client, {get, URL, Params, header}).

-spec get(pid(), string(), [proplists:property()], header | querystring) -> ok | term().
get(Client, URL, Params, ParamsMethod) ->
  gen_server:call(Client, {get, URL, Params, ParamsMethod}).

-spec access_token_params(pid()) -> [{string(), string()}].
access_token_params(Client) ->
  gen_server:call(Client, {access_token_params}).

-spec request_token_params(pid()) -> [{string(), string()}].
request_token_params(Client) ->
  gen_server:call(Client, {request_token_params}).

-spec deauthorize(pid()) -> ok.
deauthorize(Client) ->
  gen_server:cast(Client, deauthorize).

-spec stop(pid()) -> ok.
stop(Client) ->
  gen_server:cast(Client, stop).

%%============================================================================
%% Helper functions
%%============================================================================
-spec oauth_get(header|querystring, string(), [proplists:property()], tuple(), string(), string()) -> {ok, {{string(), integer(), string()}, [{string(), string()}], iolist()}} | any().
oauth_get(header, URL, Params, Consumer, Token, TokenSecret) ->
  Signed = oauth:signed_params("GET", URL, Params, Consumer, Token, TokenSecret),
  {AuthorizationParams, QueryParams} = lists:partition(fun({K, _}) -> lists:prefix("oauth_", K) end, Signed),
  Request = {oauth:uri(URL, QueryParams), [oauth:header(AuthorizationParams)]},
  httpc:request(get, Request, [{autoredirect, false}, {ssl, [{ssl_imp, old}]}], []);
oauth_get(querystring, URL, Params, Consumer, Token, TokenSecret) ->
  oauth:get(URL, Params, Consumer, Token, TokenSecret).

%%============================================================================
%% gen_server callbacks
%%============================================================================

-spec init(term()) -> {ok, state()}.
init(Consumer) ->
  {ok, {Consumer}}.

-spec handle_call(term(), reference(), state()) -> {reply, term(), state()}.
handle_call({get_request_token, URL, Params, ParamsMethod}, _From, State={Consumer}) ->
  case oauth_get(ParamsMethod, URL, Params, Consumer, "", "") of
    {ok, Response} ->
      case oauth_http:response_code(Response) of
        200 ->
          RParams = oauth_http:response_params(Response),
          {reply, {ok, oauth:token(RParams)}, {Consumer, RParams}};
        _ ->
          {reply, Response, State}
      end;
    Error ->
      {reply, Error, State}
  end;
handle_call({get_access_token, URL, Params, ParamsMethod}, _From, State={Consumer, RParams}) ->
  case oauth_get(ParamsMethod, URL, Params, Consumer, oauth:token(RParams), oauth:token_secret(RParams)) of
    {ok, Response} ->
      case oauth_http:response_code(Response) of
        200 ->
          AParams = oauth_http:response_params(Response),
          {reply, ok, {Consumer, RParams, AParams}};
        _ ->
          {reply, Response, State}
      end;
    Error ->
      {reply, Error, State}
  end;
handle_call({get, URL, Params, ParamsMethod}, _From, State={Consumer, _RParams, AParams}) ->
  case oauth_get(ParamsMethod, URL, Params, Consumer, oauth:token(AParams), oauth:token_secret(AParams)) of
    {ok, Response={{_, Status, _}, Headers, Body}} ->
      case Status of
        200 ->
          case proplists:get_value("content-type", Headers) of
            undefined ->
              {reply, {ok, Headers, Body}, State};
            ContentType ->
              MediaType = hd(string:tokens(ContentType, ";")),
              case lists:suffix("/xml", MediaType) orelse lists:suffix("+xml", MediaType) of
                true ->
                  {XML, []} = xmerl_scan:string(Body),
                  {reply, {ok, Headers, XML}, State};
                false ->
                  {reply, {ok, Headers, Body}, State}
              end
          end;
        _ ->
          {reply, Response, State}
      end;
    Error ->
      {reply, Error, State}
  end;
handle_call({access_token_params}, _From, State={_Consumer, _RParams, AParams}) ->
  {reply, AParams, State};
handle_call({request_token_params}, _From, State={_Consumer, RParams}) ->
  {reply, RParams, State}.

-spec handle_cast(term(), state()) -> {noreply, state()} | {stop, normal, state()}.
handle_cast(deauthorize, {Consumer, _RParams}) ->
  {noreply, {Consumer}};
handle_cast(deauthorize, {Consumer, _RParams, _AParams}) ->
  {noreply, {Consumer}};
handle_cast(stop, State) ->
  {stop, normal, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Msg, State) ->
  {noreply, State}.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

-spec terminate(term(), state()) -> ok.
terminate(normal, _State) ->
  ok.
