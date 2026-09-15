# Nuclei Template: Qdrant UI - Unauthenticated Access
**Template ID:** unauth-qdrantui
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-qdrantui.yaml`)

## Vulnerability Information & PoC

## Description
Qdrant UI Dashboard was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/collections
```

