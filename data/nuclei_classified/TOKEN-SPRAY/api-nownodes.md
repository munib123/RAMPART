# Vulnerability: Nownodes API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-nownodes.yaml`)

## Description
Blockchain-as-a-service solution that provides high-quality connection via API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bsc-blockbook.nownodes.io/api HTTP/1.1
Host: bsc-blockbook.nownodes.io
api-key: {{token}}
Content-Type: application/json
```

