# Vulnerability: Array Networks SSL VPN - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`array-networks-ssl-vpn-panel.yaml`)

## Description
Array Networks AG Series SSL VPN appliances provide enterprise remote access.
The web login portal (Pilot) is typically accessible on port 8889 or via /prx/ paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

