# Vulnerability: Flowdash API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-flowdash.yaml`)

## Description
Automate business workflows

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://app.flowdash.com/api/v1/workflows HTTP/1.1
Host: app.flowdash.com
Authorization: Bearer {{token}}
```

