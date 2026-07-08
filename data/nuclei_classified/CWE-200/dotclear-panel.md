# Vulnerability: Dotclear Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dotclear-panel.yaml`)

## Description
Dotclear admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dc2/admin/auth.php
GET {{BaseURL}}/auth.php
```

