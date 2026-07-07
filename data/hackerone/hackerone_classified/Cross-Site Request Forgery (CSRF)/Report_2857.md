# HackerOne Report: CSRF token valid even after the session logout of a particular user
**Report ID:** 2857
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi,

To reproduce the issue:

1) Login to your https://secure.phabricator.com account and copy your Anti CSRF token.

2) Now logout and again login after sometime.

3) Open up your burp suite to modify the request and now submit any form with your old CSRF token.

The request will be completed.

So let's suppose i am somehow able to get CSRF token of a particular user then i can use the same token again and again to perform the attack.

The token should be thrown from the db after the session logout.

Please have a look.

Best regards,
Anand


## Discussion & Remediation Timeline
