# HackerOne Report: X-Content-Type-Options header missing
**Report ID:** 8059
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
URL :  http://www.localize.io/

Description : The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'

Solution : This check is specific to Internet Explorer 8 and Google Chrome. Ensure each page sets a Content-Type header and the X-CONTENT-TYPE-OPTIONS if the Content-Type header is unknown

content sniffing is possible

## Discussion & Remediation Timeline
