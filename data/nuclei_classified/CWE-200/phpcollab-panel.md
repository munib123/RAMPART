# Vulnerability: phpCollab Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phpcollab-panel.yaml`)

## Description
phpCollab login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/general/login.php
```

