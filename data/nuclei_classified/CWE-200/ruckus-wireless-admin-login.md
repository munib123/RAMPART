# Vulnerability: Ruckus Wireless Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ruckus-wireless-admin-login.yaml`)

## Description
Ruckus Wireless admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.asp
```

