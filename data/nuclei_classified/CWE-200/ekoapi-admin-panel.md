# Vulnerability: EkoAPI Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ekoapi-admin-panel.yaml`)

## Description
EkoAPI Admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

