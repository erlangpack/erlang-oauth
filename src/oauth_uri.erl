-module(oauth_uri).

-export([join/1, normalize/1]).


join({Scheme, UserInfo, Host, Port, Path, Query}) ->
  join(Scheme, UserInfo, Host, Port, [Path, Query]).

join(http, UserInfo, Host, 80, URI) ->
  join(http, UserInfo, [Host|URI]);
join(https, UserInfo, Host, 443, URI) ->
  join(https, UserInfo, [Host|URI]);
join(Scheme, UserInfo, Host, Port, URI) ->
  join(Scheme, UserInfo, [Host, ":", Port|URI]).

join(Scheme, [], URI) ->
  lists:concat([Scheme, "://"|URI]);
join(Scheme, UserInfo, URI) ->
  lists:concat([Scheme, "://", UserInfo, "@"|URI]).

normalize(URI) ->
  case http_uri:parse(URI) of
    {error, _Reason} ->
      URI;
    Parts ->
      join(Parts)
  end.
