# Vulnerability: NocoDB Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`nocodb-panel.yaml`)

## Description
NocoDB Login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard/#/signin
GET {{BaseURL}}/dashboard/favicon.ico
```

