# Vulnerability: SGP Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sgp-login-panel.yaml`)

## Description
SGP login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/accounts/login?next=/admin/
```

