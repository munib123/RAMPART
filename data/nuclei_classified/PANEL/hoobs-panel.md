# Vulnerability: HOOBS Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`hoobs-panel.yaml`)

## Description
HOOBS is a home automation platform that bridges HomeKit and non-HomeKit devices.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?url=%2F
```

