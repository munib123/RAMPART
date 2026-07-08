# Vulnerability: Plesk Obsidian Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`plesk-obsidian-login.yaml`)

## Description
Plesk Obsidian login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login_up.php
```

