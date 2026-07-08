# Vulnerability: Monday API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-monday.yaml`)

## Description
Programmatically access and update data inside a monday.com account

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.monday.com/v2 HTTP/1.1
Host: api.monday.com
Authorization: {{token}}
Content-Type: application/json

{"query": "query { me { is_guest created_at name id}}"}
```

