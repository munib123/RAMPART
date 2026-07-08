# Vulnerability: WireGuard Easy (wg-easy) - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`wg-easy-panel.yaml`)

## Description
wg-easy is the easiest way to run WireGuard VPN with a web-based admin UI.
It exposes a management interface for creating and managing WireGuard peers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

