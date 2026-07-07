# HackerOne Report: http://jetpack.me/ Self XSS
**Report ID:** 14303
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi there :)

I found a self XSS located at the front page of http://jetpack.me/, To reproduce this you have to scroll to the `Every feature!` part and search for `<img src=x onerror=alert(1)>` in the search engine.

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
