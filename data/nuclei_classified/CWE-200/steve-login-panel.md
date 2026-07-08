# Vulnerability: SteVe Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`steve-login-panel.yaml`)

## Description
SteVe login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/manager/signin
GET {{BaseURL}}/steve/manager/signin
```

