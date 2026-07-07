# HackerOne Report: External URL page bypass
**Report ID:** 63158
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
A specially crafted URL can bypass the external URL warning page.

# Details

A url that starts with two forward slashes is treated as absolute by browsers.  The markdown renderer refuses to render links that start like this, however it can be tricked by using a control character e.g.

"[test](/\x08/evil.com)"

## Discussion & Remediation Timeline
