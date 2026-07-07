# HackerOne Report: /index.php/dashboard/sitemap/explore/ Cross-site scripting
**Report ID:** 4808
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

When you go to /index.php/dashboard/sitemap/explore/ and press on blog (I had standing Blog there) and then on properties -> Custom Attributes -> tags and insert "><img src=x onerror=alert(4)> a XSS will popup.

Some screens are in the attachment.

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
