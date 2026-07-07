# HackerOne Report: Anti-MIME-Sniffing header X-Content-Type-Options header has not been set.
**Report ID:** 9479
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hi,

The following host "profile-photos-user-content.hackerone.com" does not set the x-content-type-options header to nosniff. If a malicious user is able to upload an image with script content (Possible within the comments metadata) Internet Explorer (up till IE8) might render the content as Javascript and execute malicious code.

The problem is more severe since the photos are uploaded to a subdomain of hackerone.com.

Cheers,

## Discussion & Remediation Timeline
