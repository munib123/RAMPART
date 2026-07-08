# Vulnerability: SQLPad Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`sqlpad-panel.yaml`)

## Description
SQLPad panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/signin
```

