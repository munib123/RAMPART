# Vulnerability: AlienVault USM Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`alienvault-usm.yaml`)

## Description
An AlienVault USM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ossim/session/login.php
```

