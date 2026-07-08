# Vulnerability: Supportivekoala API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-supportivekoala.yaml`)

## Description
Autogenerate images with template

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.supportivekoala.com/v1/images HTTP/1.1
Host: api.supportivekoala.com
Content-Type: application/json
Authorization: Bearer {{token}}
```

