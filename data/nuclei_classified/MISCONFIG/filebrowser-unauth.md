# Vulnerability: File Browser Dashboard - Unauthenticated Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`filebrowser-unauth.yaml`)

## Description
File Browser dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

