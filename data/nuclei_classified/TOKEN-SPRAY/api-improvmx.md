# Vulnerability: ImprovMX API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-improvmx.yaml`)

## Description
API for free email forwarding service

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.improvmx.com/v3/account HTTP/1.1
Authorization: Basic {{base64(':' + token)}}
Host: api.improvmx.com
```

