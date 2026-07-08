# Vulnerability: Kentico Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kentico-login.yaml`)

## Description
Kentico login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CMSPages/logon.aspx
```

