# Nuclei Template: Lucee - Unset Credentials
**Template ID:** lucee-unset-credentials
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`lucee-unset-credentials.yaml`)

## Vulnerability Information & PoC

## Description
The Lucee admin panel has a first-time setup page which allows any user to set the administrator password.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/lucee/admin/web.cfm
GET {{BaseURL}}/lucee/admin/server.cfm
```

## References
- https://luceeserver.atlassian.net/browse/LDEV-926
- https://www.petefreitag.com/blog/lucee-admin-password-box/
