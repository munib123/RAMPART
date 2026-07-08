# Vulnerability: Moxa OnCell VPN - Login Panel
**Classification:** MOXO
**Source:** Nuclei Template (`moxa-vpn-router-panel.yaml`)

## Description
Moxa OnCell VPN panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login.asp
```

