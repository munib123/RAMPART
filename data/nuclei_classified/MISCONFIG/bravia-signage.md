# Vulnerability: BRAVIA Signage - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`bravia-signage.yaml`)

## Description
Bravia Signage is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/settings
```

