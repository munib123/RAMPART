# Vulnerability: Enablix Panel - Detect
**Classification:** ENABLIX
**Source:** Nuclei Template (`enablix-panel.yaml`)

## Description
Enablix panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html#/login
```

