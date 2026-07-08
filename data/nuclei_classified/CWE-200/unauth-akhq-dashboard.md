# Vulnerability: AKHQ Dashboard - Unauthenticated Access
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-akhq-dashboard.yaml`)

## Description
AKHQ Dashboard was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/me
```

