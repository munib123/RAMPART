# Vulnerability: block.io API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-block.yaml`)

## Description
Bitcoin Payment, Wallet & Transaction Data

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://block.io/api/v2/get_balance/?api_key={{token}}
```

