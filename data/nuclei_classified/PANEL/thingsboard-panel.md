# Vulnerability: ThingsBoard Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`thingsboard-panel.yaml`)

## Description
ThingsBoard was detected — a Open-source IoT Platform for device management, data collection, processing and visualization.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

