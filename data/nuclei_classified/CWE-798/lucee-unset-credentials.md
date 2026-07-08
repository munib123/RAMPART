# Vulnerability: Lucee - Unset Credentials
**Classification:** CWE-798
**Source:** Nuclei Template (`lucee-unset-credentials.yaml`)

## Description
The Lucee admin panel has a first-time setup page which allows any user to set the administrator password.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lucee/admin/web.cfm
GET {{BaseURL}}/lucee/admin/server.cfm
```

