# Vulnerability: Horde Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`horde-login-panel.yaml`)

## Description
Horde login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/horde/login.php
GET {{BaseURL}}/login.php
```

