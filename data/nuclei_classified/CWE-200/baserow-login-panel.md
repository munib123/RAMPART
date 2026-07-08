# Vulnerability: Baserow Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`baserow-login-panel.yaml`)

## Description
Baserow login interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

