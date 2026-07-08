# Vulnerability: Pinata API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-pinata.yaml`)

## Description
IPFS Pinning Services API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.pinata.cloud/data/pinList?status=pinned HTTP/1.1
Host: api.pinata.cloud
pinata_api_key: {{token}}
pinata_secret_api_key: {{secret}}
```

