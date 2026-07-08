# Vulnerability: ClickUp API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-clickup.yaml`)

## Description
ClickUp is a robust, cloud-based project management tool for boosting productivity

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.clickup.com/api/v2/user HTTP/1.1
Host: api.clickup.com
Authorization: {{token}}
```

