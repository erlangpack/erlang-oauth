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


How do I use it?
----------------

The crypto and inets applications need to be running, and---as it's easy to
forget---all the code needs to be compiled. A typical authentication flow
would be similar to the following:

  ConsumerKey = "key",

  ConsumerSecret = "secret",

  SignatureMethod = "HMAC-SHA1",

  Consumer = oauth_consumer:new(ConsumerKey, ConsumerSecret, SignatureMethod),

  HttpResponse = oauth:get(RequestTokenURL, Consumer),

  RequestTokenPair = oauth_token_pair:new(HttpResponse),

  % If necessary, direct user to the Service Provider,
  % with RequestToken = element(1, RequestTokenPair).

  HttpResponse2 = oauth:get(AccessTokenURL, Consumer, RequestTokenPair),

  AccessTokenPair = oauth_token_pair:new(HttpResponse2),

  oauth:get(ProtectedResourceURL, Consumer, AccessTokenPair, ExtraParams).


Calling oauth:get or oauth:post returns an HTTP response tuple, as returned
from http:request/4. Type "make termie", or look at the oauth_termie module
for a working example. Thanks Andy!

Alternatively, you can use oauth_request:header/6 to generate an HTTP
Authorization header, as described by http://oauth.net/core/1.0/#auth_header.
This isn't (currently) integrated into oauth:get and oauth:post, so you would
need to use http:request/4 directly in this case.


Who can I contact if I have another question?
---------------------------------------------

Tim Fletcher (http://tfletcher.com/).
