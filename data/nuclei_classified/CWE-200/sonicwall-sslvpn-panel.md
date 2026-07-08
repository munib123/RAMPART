# Vulnerability: SonicWall Virtual Office SSL VPN Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sonicwall-sslvpn-panel.yaml`)

## Description
SonicWall Virtual Office SSL VPN login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/welcome
```

