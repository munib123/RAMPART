# HackerOne Report: XSS via Fabrico Account Name
**Report ID:** 34725
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
O.S: Windows 8
Browser: Google Chrome

Steps to reproduce:
1) Inject This Payload while Signing Up your account at fabrico
#"><img src=x onerror=alert(2);>
2) After the Confirmation, Activate your account 

That's it Pop Will indicate XSS vulnerability


## Discussion & Remediation Timeline
