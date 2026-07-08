# Vulnerability: Zenario Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zenario-login-panel.yaml`)

## Description
Zenario admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zenario/admin/welcome.php
```

