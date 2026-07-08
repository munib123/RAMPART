# Vulnerability: Creatio Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`creatio-login-panel.yaml`)

## Description
Creatio login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login/NuiLogin.aspx
```

