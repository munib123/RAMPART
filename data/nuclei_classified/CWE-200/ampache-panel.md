# Vulnerability: Ampache Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ampache-panel.yaml`)

## Description
Ampache login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login.php
GET {{BaseURL}}/public/login.php
```

