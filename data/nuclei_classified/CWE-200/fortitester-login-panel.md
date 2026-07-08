# Vulnerability: Fortinet FortiTester Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortitester-login-panel.yaml`)

## Description
Fortinet FortiTester login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
GET {{BaseURL}}/index.html
```

