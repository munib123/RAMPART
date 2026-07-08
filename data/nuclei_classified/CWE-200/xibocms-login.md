# Vulnerability: Xibo CMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xibocms-login.yaml`)

## Description
Xibo CMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

