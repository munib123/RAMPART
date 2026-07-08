# Vulnerability: RESA Vista Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`resa-vista-panel.yaml`)

## Description
RESA Vista was detected — an automated multimedia display system for airports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/account/login
```

