# Vulnerability: SPIP Install - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`spip-install.yaml`)

## Description
SPIP is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ecrire/?exec=install
```

