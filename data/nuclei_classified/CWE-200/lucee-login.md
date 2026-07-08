# Vulnerability: Lucee Web and Lucee Server Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lucee-login.yaml`)

## Description
Lucee admin login panels were detected in both Web and Server tabs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lucee/admin/web.cfm
GET {{BaseURL}}/lucee/admin/server.cfm
```

