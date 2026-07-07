# HackerOne Report: CSP not consistently applied
**Report ID:** 321
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Also thought I'd formally submitted the issue we discussed yesterday, that sometimes the CSP response headers served are missing for browsers that don't support them, but then the page without these headers can be cached by Cloudflare. This makes it easier to mount a XSS attack.

## Discussion & Remediation Timeline
