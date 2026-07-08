# Vulnerability: OpenVPN Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openvpn-admin.yaml`)

## Description
OpenVPN Admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
GET {{BaseURL}}/index.php
```

