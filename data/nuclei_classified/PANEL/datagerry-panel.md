# Vulnerability: Datagerry Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`datagerry-panel.yaml`)

## Description
Datagerry panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth
GET {{BaseURL}}
```

