# HackerOne Report: Stored XSS
**Report ID:** 7873
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hey!!

Steps to reproduce :

1) while making account add xss payload in username like : "><img src=a onerror=prompt(1);>
2) login using this .
3) Go to settings tab (http://www.localize.io/pages/settings)
4) XSS ll get executed .

Attached PoC .

Daksh

## Discussion & Remediation Timeline
