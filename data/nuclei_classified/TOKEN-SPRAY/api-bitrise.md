# Vulnerability: Bitrise API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-bitrise.yaml`)

## Description
Build tool and processes integrations to create efficient development pipelines

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.bitrise.io/v0.1/me HTTP/1.1
Host: api.bitrise.io
Authorization: {{token}}
```

