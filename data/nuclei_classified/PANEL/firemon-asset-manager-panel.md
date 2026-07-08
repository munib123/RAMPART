# Vulnerability: FireMon Asset Manager - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`firemon-asset-manager-panel.yaml`)

## Description
FireMon Asset Manager is a network security management platform that provides visibility, policy management, and compliance reporting for firewalls, routers, and other network security infrastructure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

