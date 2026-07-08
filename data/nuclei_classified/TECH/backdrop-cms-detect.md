# Vulnerability: Backdrop CMS - Detect
**Classification:** TECH
**Source:** Nuclei Template (`backdrop-cms-detect.yaml`)

## Description
Backdrop CMS was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/core/profiles/testing/testing.info
```

