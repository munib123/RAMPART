# Vulnerability: PAN-OS Management Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`panos-management-panel.yaml`)

## Description
PAN-OS management panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/php/login.php
```

