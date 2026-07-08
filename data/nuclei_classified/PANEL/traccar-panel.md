# Vulnerability: Traccar Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`traccar-panel.yaml`)

## Description
Traccar panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

