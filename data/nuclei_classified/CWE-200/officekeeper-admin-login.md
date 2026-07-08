# Vulnerability: OfficeKeeper Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`officekeeper-admin-login.yaml`)

## Description
OfficeKeeper admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

