# Vulnerability: Homebridge Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`homebridge-panel.yaml`)

## Description
Homebridge allows you to integrate with smart home devices that do not natively support HomeKit.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

