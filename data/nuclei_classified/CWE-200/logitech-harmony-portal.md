# Vulnerability: Logitech Harmony Pro Installer Portal Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`logitech-harmony-portal.yaml`)

## Description
Logitech Harmony Pro Installer Portal login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/login
```

