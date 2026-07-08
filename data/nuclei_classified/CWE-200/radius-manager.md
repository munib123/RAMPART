# Vulnerability: Radius Manager Admininstration Control Panel Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`radius-manager.yaml`)

## Description
Radius Manager Administration Control Panel login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/admin.php
GET {{BaseURL}}/radiusmanager/user.php
GET {{BaseURL}}/user.php
```

