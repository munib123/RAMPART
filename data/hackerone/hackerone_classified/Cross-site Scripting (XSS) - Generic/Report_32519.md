# HackerOne Report: XSS in fabric.io
**Report ID:** 32519
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Proof: http://i.imgur.com/Hk84G3Y.png

Vulnerable Page: https://fabric.io/onboard/invite
Put this code: "><img src=x onerror=alert(document.domain)>
and email
then send invitation


## Discussion & Remediation Timeline
