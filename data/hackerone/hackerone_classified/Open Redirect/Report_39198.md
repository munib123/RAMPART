# HackerOne Report: [admin.c2fo.com] Open Redirect
**Report ID:** 39198
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
PoC (FireFox):
https://admin.c2fo.com///www.google.com/%2e%2e

HTTP Request:
GET ///www.google.com/%2e%2e HTTP/1.1
Host: admin.c2fo.com

HTTP Response:
Location: //www.google.com/%2e%2e/


## Discussion & Remediation Timeline
