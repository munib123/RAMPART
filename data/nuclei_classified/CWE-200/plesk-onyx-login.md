# Vulnerability: Plesk Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`plesk-onyx-login.yaml`)

## Description
Plesk login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login_up.php
```

