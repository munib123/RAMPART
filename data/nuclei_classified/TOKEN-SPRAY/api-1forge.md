# Vulnerability: 1Forge API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-1forge.yaml`)

## Description
Forex currency market data

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.1forge.com/quota?api_key={{token}}
```

