# Vulnerability: AdminBro Dashboard - Unauthenticated Access
**Classification:** CWE-306
**Source:** Nuclei Template (`adminbro-dashboard-exposure.yaml`)

## Description
Detected AdminBro/AdminJS admin panel was exposed without authentication, allowing unauthenticated users to access the admin dashboard and potentially view, modify, or delete sensitive data. This misconfiguration occurred when developers used buildRouter() instead of buildAuthenticatedRouter().

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
GET {{BaseURL}}/admin/
```

