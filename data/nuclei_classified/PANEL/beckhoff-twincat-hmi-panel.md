# Vulnerability: Beckhoff TwinCAT HMI Server - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`beckhoff-twincat-hmi-panel.yaml`)

## Description
Beckhoff TwinCAT HMI (Human Machine Interface) Server is part of the TwinCAT
industrial automation platform used in manufacturing, robotics, and process
automation. It exposes a web-based HMI accessible via browser for monitoring
and controlling PLC-driven systems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

