# Vulnerability: CradlePoint Gateway - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`cradlepoint-gateway-panel.yaml`)

## Description
CradlePoint (an Ericsson company) produces cellular-connected SD-WAN and VPN
gateway appliances. The web administration interface is commonly exposed on
port 8080.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

