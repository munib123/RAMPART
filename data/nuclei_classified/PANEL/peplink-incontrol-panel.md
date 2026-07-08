# Vulnerability: Peplink InControl - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`peplink-incontrol-panel.yaml`)

## Description
Peplink InControl is a centralised cloud-based SD-WAN and device management platform for Peplink routers and access points, enabling remote configuration, monitoring, and SpeedFusion VPN management across distributed sites.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

