# Vulnerability: Todoist API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-todoist.yaml`)

## Description
Todo Lists

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.todoist.com/rest/v1/projects HTTP/1.1
Host: api.todoist.com
Authorization: Bearer {{token}}
```

