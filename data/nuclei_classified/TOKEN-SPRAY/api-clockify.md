# Vulnerability: Clockify API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-clockify.yaml`)

## Description
Clockify's REST-based API can be used to push/pull data to/from it & integrate it with other systems

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.clockify.me/api/v1/user HTTP/1.1
Host: api.clockify.me
X-Api-Key: {{token}}
Content-Type: application/json
```

