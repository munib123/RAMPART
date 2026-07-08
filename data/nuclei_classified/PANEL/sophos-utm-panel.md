# Vulnerability: Sophos UTM User Portal - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`sophos-utm-panel.yaml`)

## Description
Sophos UTM (Unified Threat Management) exposes a User Portal interface on ports 8443/5443 for SSL VPN client access and self-service.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

