# Vulnerability: WebShell4 Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`webshell4-login-panel.yaml`)

## Description
WebShell4 login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webshell4/login.php
```

