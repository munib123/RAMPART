# Vulnerability: Quip API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-quip.yaml`)

## Description
File Sharing and Storage for groups

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://platform.quip.com/1/users/current HTTP/1.1
Host: platform.quip.com
Authorization: Bearer {{token}}
```

