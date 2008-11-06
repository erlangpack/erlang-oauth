-module(oauth_util).

-compile(export_all).

-define(is_uppercase_alpha(C), C >= $A, C =< $Z).
-define(is_lowercase_alpha(C), C >= $a, C =< $z).
-define(is_alpha(C), ?is_uppercase_alpha(C); ?is_lowercase_alpha(C)).
-define(is_digit(C), C >= $0, C =< $9).
-define(is_alphanumeric(C), ?is_alpha(C); ?is_digit(C)).
-define(is_unreserved(C), ?is_alphanumeric(C); C =:= $-; C =:= $_; C =:= $.; C =:= $~).
-define(is_hex(C), ?is_digit(C); C >= $A, C =< $F).


unix_timestamp() ->
  unix_timestamp(calendar:universal_time()).

unix_timestamp(DateTime) ->
  calendar:datetime_to_gregorian_seconds(DateTime) - unix_epoch().

unix_epoch() ->
  calendar:datetime_to_gregorian_seconds({{1970,1,1},{00,00,00}}).

nonce() ->
  base64:encode_to_string(crypto:rand_bytes(32)). % cf. ruby-oauth

percent_decode(Chars) when is_list(Chars) ->
  percent_decode(Chars, []).

percent_decode([], Decoded) ->
  lists:reverse(Decoded);
percent_decode([$%,A,B|Etc], Decoded) when ?is_hex(A), ?is_hex(B) ->
  percent_decode(Etc, [erlang:list_to_integer([A,B], 16)|Decoded]);
percent_decode([C|Etc], Decoded) when ?is_unreserved(C) ->
  percent_decode(Etc, [C|Decoded]).
