# Vulnerability: ICE HRM Login - Detect
**Classification:** ICEHRM
**Source:** Nuclei Template (`ice-hrm-panel.yaml`)

## Description
The ICE HRM login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/login.php
```

