# Vulnerability: Netlify CMS Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netlify-cms.yaml`)

## Description
Netlify CMS admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/index.html
```

