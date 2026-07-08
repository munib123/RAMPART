# Vulnerability: Unauth Phoenix Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-phoenix-dashboard.yaml`)

## Description
Phoenix Dashboard was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/settings/general
```

