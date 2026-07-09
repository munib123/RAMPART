# Nuclei Template: AdminBro Dashboard - Unauthenticated Access
**Template ID:** adminbro-dashboard-exposure
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`adminbro-dashboard-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected AdminBro/AdminJS admin panel was exposed without authentication, allowing unauthenticated users to access the admin dashboard and potentially view, modify, or delete sensitive data. This misconfiguration occurred when developers used buildRouter() instead of buildAuthenticatedRouter().

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/admin
GET {{BaseURL}}/admin/
```

## References
- https://docs.adminjs.co/basics/authentication
- https://github.com/SoftwareBrothers/adminjs
