# Vulnerability: Z-BlogPHP Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zblog-exposed-admin-panel.yaml`)

## Description
Z-BlogPHP admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zb_system/login.php
```

