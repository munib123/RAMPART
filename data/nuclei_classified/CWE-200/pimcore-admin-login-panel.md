# Vulnerability: Pimcore Admin Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pimcore-admin-login-panel.yaml`)

## Description
Pimcore admin login interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

