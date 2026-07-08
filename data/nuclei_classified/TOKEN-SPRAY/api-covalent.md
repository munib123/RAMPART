# Vulnerability: Covalent API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-covalent.yaml`)

## Description
https://github.com/daffainfo/all-about-apikey/tree/main/covalent

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.covalenthq.com/v1/3/address/balances_v2/?&key={{token}}
```

