# Vulnerability: Sitecore Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sitecore-login-panel.yaml`)

## Description
Sitecore admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sitecore/admin/login.aspx
```

