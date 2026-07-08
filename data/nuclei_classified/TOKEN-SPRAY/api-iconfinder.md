# Vulnerability: IconFinder API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-iconfinder.yaml`)

## Description
Web Icons

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.iconfinder.com/v4/icons/search?query=arrow&count=10 HTTP/1.1
Host: api.iconfinder.com
Accept: application/json
Authorization: Bearer {{token}}
```

