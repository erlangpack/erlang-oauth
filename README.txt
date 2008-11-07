============
erlang-oauth
============


What is this?
-------------

An Erlang wrapper around the OAuth protocol.


What is OAuth?
--------------

An "open protocol to allow secure API authentication in a simple and standard
method from desktop and web applications". See http://oauth.net/ for more info.


What do I need?
---------------

Erlang, and erlang-fmt (http://tfletcher.com/dev/erlang-fmt).

The Makefile assumes that erlang-fmt is contained in the parent directory of
this one, so you might want to edit the Makefile if you have it elsewhere.

Erlang R12B-5 is required for RSA-SHA1 signing.


How do I use it?
----------------

First, create a consumer:

  Consumer = oauth_consumer:new("key", "secret", SignatureMethod).


SignatureMethod can either be "PLAINTEXT", "HMAC-SHA1", or {"RSA-SHA1", PK},
where PK is either a path pointing to a private key PEM file, or a tuple as
returned by public_key:decode_private_key/1.

Requests can be made with oauth:get and oauth:post, e.g.,

  Response = oauth:get(URL, Consumer).


URL must not contain a query string. Instead, pass the query parameters in
as an additional [proplist] argument, e.g.,

  Response = oauth:get(URL, Consumer, [{foo, "bar"}]).


Calling oauth:get or oauth:post returns an HTTP response tuple, as would
be returned from http:request/4. If you are requesting tokens you can use
oauth_token_pair:new/1 to extract the oauth_token and oauth_token_secret
parameters from the response, e.g.,

  TokenPair={Token, TokenSecret} = oauth_token_pair:new(Response).


TokenPair can then be passed back into oauth:get and oauth:post to
request additional tokens, or a protected resource. Alternatively, you
can use oauth_request:to_header/2,4 to generate an HTTP Authorization
header, as described by http://oauth.net/core/1.0/#auth_header. This
isn't (currently) integrated into oauth:get and oauth:post, so you
would need to use http:request/4 directly in this case.


Are there any examples anywhere?
--------------------------------

Yes. See test/oauth_termie.erl and test/oauth_google.erl. They can be
run with "make termie_hmac", "make termie_rsa", and "make google".


Who can I contact if I have another question?
---------------------------------------------

Tim Fletcher (http://tfletcher.com/).
