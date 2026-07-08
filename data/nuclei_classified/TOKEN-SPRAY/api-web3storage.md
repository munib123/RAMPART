# Vulnerability: Web3 Storage API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-web3storage.yaml`)

## Description
File Sharing and Storage for Free with 1TB Space

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.web3.storage/user/uploads HTTP/1.1
Host: api.web3.storage
Authorization: Bearer {{token}}
```

