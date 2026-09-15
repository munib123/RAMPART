# Nuclei Template: Reflected XSS
**Template ID:** xss-uri-reflected
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Low
**CWE:** CWE-79
**Source:** Nuclei Template (`xss-uri-reflected.yaml`)

## Vulnerability Information & PoC

## Description
Reflected cross-site scripting vulnerability was discovered via generic testing. Manual testing is needed to verify exploitation.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/a%22%3E%3Cinjectable%3E
GET {{BaseURL}}/a%27%3E%3Cinjectable%3E
```

