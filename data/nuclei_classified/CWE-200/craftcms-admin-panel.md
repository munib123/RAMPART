# Vulnerability: Craft CMS Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`craftcms-admin-panel.yaml`)

## Description
Craft CMS admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

