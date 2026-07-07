# HackerOne Report: Cross Site Scripting (XSS) - app.relateiq.com
**Report ID:** 2439
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
I found a XSS vulnerability in relateiq.com !
1. Go to https://app.relateiq.com/ and click "Register as a new user"
2. Agree the terms and click Continue. Now choose to connect to MS exchange (Microsoft Exchange
Click to connect MS Exchange or Office365)
3.Now enter a random email and click "Connect email"
4. You will receive a error message and 2 new inputs . In the email field put this dada@c.com"><img src=x onerror=alert(document.domain)>  and in the "Override Endpoint Address" put a random website (eg:google.com)
5.Now click on "Connect email" and you will see the XSS alert.

## Discussion & Remediation Timeline
