# HackerOne Report: Options Method Enabled
**Report ID:** 33987
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Vuln Details:

Domain: https://vine.co/ 
I detected that OPTIONS method is allowed. This issue is reported as extra information.

Impact:
Information disclosed from this page can be used to gain additional information about the target system

Remedy:
Disable OPTIONS method in all production systems.

POC:

Request:

OPTIONS /assets/ HTTP/1.1
Cache-Control: no-cache
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.170 Safari/537.36 Netsparker
Accept-Language: en-us,en;q=0.5
X-Scanner: Netsparker
Host: vine.co
Accept-Encoding: gzip, deflate


Response:

HTTP/1.1 200 OK
Cache-Control: max-age=3600
Connection: keep-alive
Accept-Ranges: bytes
Strict-Transport-Security: max-age=631138519
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Allow: HEAD, OPTIONS, GET



## Discussion & Remediation Timeline
