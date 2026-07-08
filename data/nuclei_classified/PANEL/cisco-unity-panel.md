# Vulnerability: Cisco Unity Connection Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`cisco-unity-panel.yaml`)

## Description
A Cisco Unity Connection instance was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cuadmin/home.do
GET {{BaseURL}}
```

