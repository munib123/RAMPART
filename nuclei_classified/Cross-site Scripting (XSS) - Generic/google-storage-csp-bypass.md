# Nuclei Template: Content-Security-Policy Bypass - Google Storage
**Template ID:** google-storage-csp-bypass
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`google-storage-csp-bypass.yaml`)

## Vulnerability Information & PoC

## Description
CSP policy allows Google Storage (storage.googleapis.com) enabling malicious JavaScript execution by loading attacker-controlled files from whitelisted domain.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://0xn3va.gitbook.io/cheat-sheets/web-application/content-security-policy
- https://huntr.com/bounties/6cea89d1-39dc-4023-82fa-821f566b841a
