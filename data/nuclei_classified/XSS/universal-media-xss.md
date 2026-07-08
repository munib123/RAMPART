# Vulnerability: Universal Media Server v13.2.1 - Cross Site Scripting
**Classification:** XSS
**Source:** Nuclei Template (`universal-media-xss.yaml`)

## Description
Universal Media Server v13.2.1 CMS v2.0 was discovered to contain a reflected cross-site scripting (XSS) vulnerability.

## Secure Mitigation
Fixed in version 13.2.2

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/%3Cscript%3Ealert(document.domain)%3C/script%3E
```

