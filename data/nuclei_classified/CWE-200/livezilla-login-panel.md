# Vulnerability: LiveZilla Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`livezilla-login-panel.yaml`)

## Description
LiveZilla login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mobile/index.php
```

