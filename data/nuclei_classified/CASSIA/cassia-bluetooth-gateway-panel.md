# Vulnerability: Cassia Bluetooth Gateway Panel - Detect
**Classification:** CASSIA
**Source:** Nuclei Template (`cassia-bluetooth-gateway-panel.yaml`)

## Description
Cassia Bluetooth Gateway Management Platform login page was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cassia/login
```

