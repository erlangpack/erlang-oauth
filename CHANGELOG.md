# 1.6.0

  * Switched to using crypto:hmac/3

  * Switched to using crypto:strong_rand_bytes/1

  * Exported oauth:signature/5 function

  * Erlang/OTP R16B03 or greater now required


# 1.5.0

  * Added support for encoding binary terms as parameter values


# 1.4.0

  * Added support for new crypto:hmac/3 function

  * Moved unit tests from github.com/tim/erlang-oauth-tests


# 1.3.0

  * Added oauth:put/6 and oauth:put/7 functions


# 1.2.2

  * Added support for new tagged tuple returned by http_uri:parse/1 (R15B)


# 1.2.1

  * Updated to use a constant time algorithm to compare signature strings


# 1.2.0

  * Added oauth:get/3 and oauth:post/3 functions

  * Collapsed into just a single module


# 1.1.1

  * Updated to use the correct request parameter normalization algorithm


# 1.1.0

  * Updated to use the new public key API introduced in R14B (public_key-0.8)


# 1.0.2

  * Added oauth:get/6 and oauth:post/6 with additional HttpcOptions parameter


# 1.0.1

  * First version numbered version!
