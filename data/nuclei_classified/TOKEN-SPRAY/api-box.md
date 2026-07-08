# Vulnerability: Box API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-box.yaml`)

## Description
File Sharing and Storage Service

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.box.com/2.0/collections HTTP/1.1
Host: api.box.com
Authorization: Bearer {{token}}
```

