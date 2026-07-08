# Vulnerability: Ackee Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ackee-panel.yaml`)

## Description
self-hosted, node.js based analytics tool for those who care about privacy.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/favicon.ico
```

