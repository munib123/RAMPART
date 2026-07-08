# Vulnerability: Telecontrol Server Basic Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`telecontrol-server-basic-panel.yaml`)

## Description
Telecontrol Server Basic panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
GET {{BaseURL}}
```

