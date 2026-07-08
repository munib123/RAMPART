# Vulnerability: XPhone Connect Admin Interface - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xphoneconnect-admin-panel.yaml`)

## Description
Detects the presence of the XPhone Connect admin interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/xphoneconnect/admin/Login.aspx
```

