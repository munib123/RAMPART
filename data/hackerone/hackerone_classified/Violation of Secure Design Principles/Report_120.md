# HackerOne Report: Missing SPF for hackerone.com
**Report ID:** 120
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
There is no TXT record in DNS zone that defines Sender Policy Framework entry for domain hackerone.com. This makes it easy to spoof your e-mail address.

## Discussion & Remediation Timeline
