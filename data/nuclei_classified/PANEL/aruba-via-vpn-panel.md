# Vulnerability: Aruba VIA VPN - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`aruba-via-vpn-panel.yaml`)

## Description
Aruba VIA (Virtual Intranet Access) is HPE Aruba's SSL VPN client and gateway
solution. The web management portal exposes a login interface typically on port 4343.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/screens/wms/wms.cgi
```

