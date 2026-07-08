# Vulnerability: Bomgar Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bomgar-login-panel.yaml`)

## Description
Bomgar Login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/appliance/login.ns
```

