# HackerOne Report: Stored XSS in title of date navigation
**Report ID:** 50627
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
XSS payload can be executed and saved permanently in title of date navigation.

Poc code: "><img src=x onerror=alert(1)>

## Discussion & Remediation Timeline
