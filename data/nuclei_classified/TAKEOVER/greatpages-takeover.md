# Vulnerability: GreatPages - Takeover Detection
**Classification:** TAKEOVER
**Source:** Nuclei Template (`greatpages-takeover.yaml`)

## Description
Detects potential subdomain takeover on GreatPages.com.br by identifying the default error message shown on unclaimed pages.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

