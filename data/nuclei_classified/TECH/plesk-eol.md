# Vulnerability: Plesk End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`plesk-eol.yaml`)

## Description
Detected Plesk versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login_up.php
```

