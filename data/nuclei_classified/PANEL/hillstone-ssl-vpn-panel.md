# Vulnerability: Hillstone Networks SSL VPN - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`hillstone-ssl-vpn-panel.yaml`)

## Description
Hillstone Networks SSL VPN (SG-6000 series) is an enterprise network security
gateway with SSL VPN capabilities. The web login portal is frequently exposed
on standard HTTPS ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

