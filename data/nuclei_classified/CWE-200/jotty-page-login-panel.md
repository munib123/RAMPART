# Vulnerability: jotty·page Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jotty-page-login-panel.yaml`)

## Description
jotty·page login interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

