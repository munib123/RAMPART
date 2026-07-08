# Vulnerability: Headscale - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`headscale-panel.yaml`)

## Description
Headscale is an open-source, self-hosted implementation of the Tailscale control server.
It manages WireGuard-based mesh VPN networks and exposes a web UI for administration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

