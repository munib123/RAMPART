# Vulnerability: Sitecore Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sitecore-login.yaml`)

## Description
Sitecore login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sitecore/login/default.aspx
```

