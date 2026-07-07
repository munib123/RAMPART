# HackerOne Report: csrf
**Report ID:** 2635
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi,

Anti CSRF token to prevent CSRF attacks are missing on this link https://sehacure.slack.com/help/requests/new

A new request can be submitted by an malicious guy to the support team on behalf of the user.

The victim will never get to know.

1) Go to this link

https://sehacure.slack.com/help/requests/new

2) Open tamper data addon in firefox.
Submit the data .

3) Tamper the reuqest there are no tokens in the requests.

Best regards,
Anand



## Discussion & Remediation Timeline
