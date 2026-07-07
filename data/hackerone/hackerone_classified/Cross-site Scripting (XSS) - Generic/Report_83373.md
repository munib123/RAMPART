# HackerOne Report: owncloud.com: Cross Site Tracing
**Report ID:** 83373
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
`REQUEST:`
TRACE / HTTP/1.0
Host: owncloud.com
Cookie: 74b33b43fa`

`RESPONSE:`
HTTP/1.1 200 OK
Date: Wed, 19 Aug 2015 06:59:31 GMT
Server: Apache/2.2.17 (Linux/SUSE)
Connection: close
Content-Type: message/http

TRACE / HTTP/1.0
Host: owncloud.com
Cookie: 74b33b43fa; wordpress_test_cookie=WP+Cookie+check; _icl_current_language=en


This vulnerability can show cookie with http only flag

with xss it's a very critical attack vector


## Discussion & Remediation Timeline
