%% -*- coding: utf-8 -*-
%% -------------------------------------------------------------------
%%
%% Copyright (c) 2021 Marc Worrell
%%
%% -------------------------------------------------------------------

-module(oauth_SUITE).
-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% ------------------------------------------------------------
%% Tests list
%% ------------------------------------------------------------

all() ->
    [
        signature_base_string,
        plaintext,
        hmac_sha1,
        rsa_sha1
    ].

%% ------------------------------------------------------------
%% Init & clean
%% ------------------------------------------------------------

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%% ------------------------------------------------------------
%% Test cases
%% ------------------------------------------------------------


signature_base_string(Config) ->
    test_with(
        Config,
        "base_string_test_*",
        [method, url, params, base_string],
        fun (Method, URL, Params, BaseString) ->
            [?_assertEqual(BaseString, oauth:signature_base_string(Method, URL, Params))]
        end).

plaintext(Config) ->
    test_with(
        Config,
        "plaintext_test_*",
        [consumer, token_secret, signature],
        fun (Consumer, TokenSecret, Signature) ->
            SignatureTest = ?_assertEqual(Signature, oauth:plaintext_signature(Consumer, TokenSecret)),
            VerifyTest = ?_assertEqual(true, oauth:plaintext_verify(Signature, Consumer, TokenSecret)),
            [SignatureTest, VerifyTest]
        end).

hmac_sha1(Config) ->
  test_with(
    Config,
    "hmac_sha1_test_*",
    [base_string, consumer, token_secret, signature],
    fun (BaseString, Consumer, TokenSecret, Signature) ->
        SignatureTest = ?_assertEqual(Signature, oauth:hmac_sha1_signature(BaseString, Consumer, TokenSecret)),
        VerifyTest = ?_assertEqual(true, oauth:hmac_sha1_verify(Signature, BaseString, Consumer, TokenSecret)),
        [SignatureTest, VerifyTest]
    end).

rsa_sha1(Config) ->
    Pkey = data_path(Config, "rsa_sha1_private_key.pem"),
    Cert = data_path(Config, "rsa_sha1_certificate.pem"),
    [BaseString, Signature] = read([base_string, signature], data_path(Config, "rsa_sha1_test")),
    SignatureTest = ?_assertEqual(Signature, oauth:rsa_sha1_signature(BaseString, {"", Pkey, rsa_sha1})),
    VerifyTest = ?_assertEqual(true, oauth:rsa_sha1_verify(Signature, BaseString, {"", Cert, rsa_sha1})),
    [SignatureTest, VerifyTest].

test_with(Config, FilenamePattern, Keys, Fun) ->
    lists:flatten(
        lists:map(
            fun (Path) -> apply(Fun, read(Keys, Path)) end,
            filelib:wildcard(data_path(Config, FilenamePattern)))).

data_path(Config, Basename) ->
    DataDir = ?config(data_dir, Config),
    filename:join([DataDir, Basename]).

read(Keys, Path) ->
    {ok, Proplist} = file:consult(Path),
    [ proplists:get_value(K, Proplist) || K <- Keys ].
