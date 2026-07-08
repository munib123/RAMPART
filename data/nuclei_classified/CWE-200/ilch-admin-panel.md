# Vulnerability: Ilch CMS Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ilch-admin-panel.yaml`)

## Description
Ilch CMS admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/admin/admin/login/index/
```

