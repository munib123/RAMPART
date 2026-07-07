# HackerOne Report: Stored Xss in Feature Paragraph
**Report ID:** 50642
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
XSS payload can be executed and saved permanently in Feature Paragraph.

Poc code: "><img src=x onerror=alert(1)>

## Discussion & Remediation Timeline
