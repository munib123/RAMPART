# Vulnerability: Micro Focus Enterprise Server Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`microfocus-admin-server.yaml`)

## Description
Micro Focus Enterprise Server Admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/nps/servlet/portalservice
GET {{BaseURL}}/nds
GET {{BaseURL}}/_LOGIN_SERVER_
```

