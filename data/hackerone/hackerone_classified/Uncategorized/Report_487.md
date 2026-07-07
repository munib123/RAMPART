# HackerOne Report: DNS Cache Poisoning
**Report ID:** 487
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
I noticed if I made a request to your website, intercepted the request, and added the header...
X-Forwarded-Host: evil.com
it would redirect me to evil.com. Well, after that, I tried going to hackerone.com and I was instantly redirected to evil.com. This is a result of DNS cache poisoning.

## Discussion & Remediation Timeline
