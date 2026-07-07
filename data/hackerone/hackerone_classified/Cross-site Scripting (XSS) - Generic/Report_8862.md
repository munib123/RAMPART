# HackerOne Report: XSS in Stopthehacker support
**Report ID:** 8862
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello,

1. go to http://www.stopthehacker.com/support/
2. input "><img src=x onerror=prompt(1)> in the search box (use firefox)
3. A prompt box will appear. XSSed.

Thank you sir.

Clifford


## Discussion & Remediation Timeline
