# Vulnerability: F5 Admin Interface - Detect
**Classification:** F5
**Source:** Nuclei Template (`f5-admin-interface.yaml`)

## Description
Detects F5 Admin Interfaces.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tmui/login.jsp
```

