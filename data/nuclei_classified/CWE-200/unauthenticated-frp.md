# Vulnerability: FRPS Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauthenticated-frp.yaml`)

## Description
FRPS Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/static/
```

