# Vulnerability: Micro User Service API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-micro-user-service.yaml`)

## Description
User management and authentication

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.m3o.com/v1/user/Read HTTP/1.1
Host: api.m3o.com
Content-Type: application/json
Authorization: Bearer {{token}}
Content-Length: 21

{
  "id": "usrid-1"
}
```

