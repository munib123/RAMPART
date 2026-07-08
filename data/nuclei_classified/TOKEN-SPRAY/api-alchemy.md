# Vulnerability: Alchemy API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-alchemy.yaml`)

## Description
Ethereum Node-as-a-Service Provider

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://eth-mainnet.alchemyapi.io/v2/{{token}}
```

