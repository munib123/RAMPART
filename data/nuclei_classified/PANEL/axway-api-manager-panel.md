# Vulnerability: Axway API Manager Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`axway-api-manager-panel.yaml`)

## Description
Axway API Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/portal/v1.4/appinfo
GET {{BaseURL}}
```

