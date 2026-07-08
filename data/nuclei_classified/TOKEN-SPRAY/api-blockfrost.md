# Vulnerability: Blockfrost API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-blockfrost.yaml`)

## Description
Interaction with the Cardano mainnet and several testnets

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cardano-mainnet.blockfrost.io/api/v0/ HTTP/1.1
Host: cardano-mainnet.blockfrost.io
project_id: {{token}}
```

