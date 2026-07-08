# Vulnerability: YzmCMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`yzmcms-panel.yaml`)

## Description
YzmCMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/index/login.html
```

