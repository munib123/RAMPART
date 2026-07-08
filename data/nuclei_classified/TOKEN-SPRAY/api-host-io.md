# Vulnerability: host.io API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-host-io.yaml`)

## Description
Domains Data API for Developers

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://host.io/api/full/facebook.com?token=${{token}}
```

