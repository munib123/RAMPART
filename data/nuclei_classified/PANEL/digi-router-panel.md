# Vulnerability: Digi International Router - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`digi-router-panel.yaml`)

## Description
Digi International cellular routers expose a web management interface used in industrial IoT and remote connectivity applications.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

