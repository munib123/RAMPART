# Vulnerability: Cisco ISE Admin Login Panel - Detect
**Classification:** CISCO
**Source:** Nuclei Template (`cisco-ise-admin-panel.yaml`)

## Description
Cisco Identity Services Engine (ISE) admin login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login.jsp
```

