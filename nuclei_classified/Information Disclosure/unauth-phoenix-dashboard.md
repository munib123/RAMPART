# Nuclei Template: Unauth Phoenix Dashboard - Detect
**Template ID:** unauth-phoenix-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-phoenix-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Phoenix Dashboard was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/settings/general
```

