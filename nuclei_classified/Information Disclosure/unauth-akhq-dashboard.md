# Nuclei Template: AKHQ Dashboard - Unauthenticated Access
**Template ID:** unauth-akhq-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-akhq-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
AKHQ Dashboard was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/me
```

