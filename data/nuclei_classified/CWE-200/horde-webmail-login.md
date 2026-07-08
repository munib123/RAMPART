# Vulnerability: Horde Webmail Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`horde-webmail-login.yaml`)

## Description
Horde Webmail login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/horde/imp/login.php
GET {{BaseURL}}/imp/login.php
```

