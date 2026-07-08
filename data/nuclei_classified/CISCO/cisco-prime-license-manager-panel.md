# Vulnerability: Cisco Prime License Manager - Detect
**Classification:** CISCO
**Source:** Nuclei Template (`cisco-prime-license-manager-panel.yaml`)

## Description
Detected exposed Cisco Prime License Manager portals

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/elm-admin/
```

