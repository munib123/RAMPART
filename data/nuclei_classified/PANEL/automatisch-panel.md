# Vulnerability: Automatisch Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`automatisch-panel.yaml`)

## Description
The open source Zapier alternative.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

