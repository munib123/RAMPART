# Vulnerability: Airtable API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-airtable.yaml`)

## Description
Integrate with Airtable

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.airtable.com/v0/meta/bases HTTP/1.1
Host: api.airtable.com
Authorization: Bearer {{token}}
```

