# Vulnerability: Rallly Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rallly-login-panel.yaml`)

## Description
Rallly login interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

