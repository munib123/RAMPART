# Vulnerability: Endian Firewall - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`endian-firewall-panel.yaml`)

## Description
Endian Firewall Community is an open-source UTM (Unified Threat Management) appliance
and VPN gateway. The web management interface is commonly exposed on port 10443 with
a self-signed certificate.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

