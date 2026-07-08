# Vulnerability: UserGate NGFW/UTM Admin Panel - Detect
**Classification:** DETECT
**Source:** Nuclei Template (`usergate-ngfw-admin-panel.yaml`)

## Description
Detect UserGate NGFW/UTM Admin Panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/static/console-utm-webui/js/preinit.js
```

