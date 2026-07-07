# HackerOne Report: Minor Bug: Public un-compiled CSS with original sass, versioning, source map, comments, etc.
**Report ID:** 90367
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
A stylesheet is available in a non-minified, non-compiled format. It includes sass, versioning, a source map, a style guide, comments, etc. (see base64 encoded string at the very end of the document).

https://hackerone.com/assets/application.css

This alone is obviously not an exploit. However, it can divulge information under the pretense that original sass, style guide, comments, etc. are private and thus are an appropriate medium for not-so-public things. In other words, it can lead to some interesting internal information disclosure.

## Discussion & Remediation Timeline
