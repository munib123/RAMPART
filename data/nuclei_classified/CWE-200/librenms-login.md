# Vulnerability: LibreNMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`librenms-login.yaml`)

## Description
LibreNMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

