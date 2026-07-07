# HackerOne Report: Multiple Reflected Cross Site Scripting Vulnerabilities in Concrete5 version 5.7.3.1
**Report ID:** 59661
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Concrete5 is vulnerable to some reflected Cross Site Scripting (XSS) attacks because certain user input is being used within the output it generates without validating or encoding it.

## Discussion & Remediation Timeline
