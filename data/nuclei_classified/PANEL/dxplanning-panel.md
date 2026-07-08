# Vulnerability: DXPlanning Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`dxplanning-panel.yaml`)

## Description
DXPlanning was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/DxPlanning/WebBooking/Version
```

