# Vulnerability: FeatherPanel Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`featherpanel-panel.yaml`)

## Description
FeatherPanel login interface was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

