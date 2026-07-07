# HackerOne Report: CSRF on add comment section
**Report ID:** 2638
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC


Hi,

Steps to repro:

1) Go to this link https://sehacure.slack.com/help/requests/237956

2) The malicious guy should now the request number and the username.

3) Open Tamper data using tamper data firefox addon,Fill the reply in the form.

4) Submit the request.You will see there are no anti-csrf token in the request.

Impact:

Submit a lot of fake response from the victim account.

Please have a look.

Best,
Anand

## Discussion & Remediation Timeline
