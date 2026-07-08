# Vulnerability: Fortinet FortiGate SSL VPN Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`fortinet-fortigate-panel.yaml`)

## Description
Detect FortiGate SSL VPN login and extract release date.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

