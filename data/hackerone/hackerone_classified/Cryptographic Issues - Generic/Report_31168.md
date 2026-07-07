# HackerOne Report: Cryptographic Side Channel in OAuth Library
**Report ID:** 31168
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
Because hashes and tokens are compared with the `!==` and `===` operators, these checks may be susceptible to timing attacks. More info: http://codahale.com/a-lesson-in-timing-attacks/

Affected code:

https://github.com/WP-API/OAuth1/blob/45197eca2925f5022192903d3639decd0ae1811c/lib/class-wp-json-authentication-oauth1.php#L562
https://github.com/WP-API/OAuth1/blob/45197eca2925f5022192903d3639decd0ae1811c/lib/class-wp-json-authentication-oauth1.php#L290

## Discussion & Remediation Timeline
