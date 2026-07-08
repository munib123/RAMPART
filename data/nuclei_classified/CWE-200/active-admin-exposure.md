# Vulnerability: ActiveAdmin Admin Dasboard Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`active-admin-exposure.yaml`)

## Description
An ActiveAdmin Admin dashboard was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

