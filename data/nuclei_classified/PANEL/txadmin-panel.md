# Vulnerability: txAdmin Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`txadmin-panel.yaml`)

## Description
txAdmin panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth
```

