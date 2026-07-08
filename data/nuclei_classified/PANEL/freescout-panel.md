# Vulnerability: FreeScout Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`freescout-panel.yaml`)

## Description
FreeScout panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

