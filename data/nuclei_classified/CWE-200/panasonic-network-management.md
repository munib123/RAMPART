# Vulnerability: Panasonic Network Camera Management System - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`panasonic-network-management.yaml`)

## Description
Panasonic Network Camera Management System page with live views was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/cam_portal.cgi
```

