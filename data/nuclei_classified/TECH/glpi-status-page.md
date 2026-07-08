# Vulnerability: GLPI Status Page - Detect
**Classification:** TECH
**Source:** Nuclei Template (`glpi-status-page.yaml`)

## Description
A php status page that indicates if local or ldap identity is used for glpi.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status.php
```

