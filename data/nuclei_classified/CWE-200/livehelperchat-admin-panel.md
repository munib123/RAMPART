# Vulnerability: Live Helper Chat Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`livehelperchat-admin-panel.yaml`)

## Description
Live Helper Chat admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/site_admin/user/login
```

