# Vulnerability: Unauth Supervisor Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-supervisor-dashboard.yaml`)

## Description
Supervisor Dashboard was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

