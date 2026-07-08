# Vulnerability: Celonis Login - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`celonis-login-panel.yaml`)

## Description
Detects Celonis Process Intelligence login panels.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/welcome
```

