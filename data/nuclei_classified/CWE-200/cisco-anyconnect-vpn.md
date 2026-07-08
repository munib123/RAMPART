# Vulnerability: Cisco AnyConnect VPN Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-anyconnect-vpn.yaml`)

## Description
Cisco AnyConnect VPN panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CACHE/sdesktop/data.xml
```

