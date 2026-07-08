# Vulnerability: Sage X3 Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sage-panel.yaml`)

## Description
Sage X3 login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login/page
```

