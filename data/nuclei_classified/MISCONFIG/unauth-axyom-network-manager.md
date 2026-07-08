# Vulnerability: Unauthenticated Axyom Network Manager
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-axyom-network-manager.yaml`)

## Description
Axyom Network Manager exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/home
```

