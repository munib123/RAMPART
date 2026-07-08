# Vulnerability: Skeepers Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`skeepers-panel.yaml`)

## Description
Skeepers login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/backend/login
GET {{BaseURL}}
```

