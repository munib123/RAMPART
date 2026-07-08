# Vulnerability: DEOS OPENview Admin Panel Unauthenticated Access
**Classification:** CWE-284
**Source:** Nuclei Template (`deos-openview-admin.yaml`)

## Description
The DEOS OPENview administrative panel is accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/client/index.html
```

