# HackerOne Report: Find, private notes Cross-site scripting.
**Report ID:** 7917
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi.

When I go to the find page and insert a `private note`, with as content : `<img src='x' onerror='alert(4)'` it will execute directly.

As preview :
1.) http://prntscr.com/3axvz5
2.) http://prntscr.com/3axw3k

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
