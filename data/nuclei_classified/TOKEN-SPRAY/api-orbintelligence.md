# Vulnerability: ORB Intelligence API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-orbintelligence.yaml`)

## Description
Company lookup

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.orb-intelligence.com/3/fetch/1/?api_key={{token}}
```

