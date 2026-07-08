# Vulnerability: PrexView API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-prexview.yaml`)

## Description
Data from XML or JSON to PDF, HTML or Image

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.prexview.com/v1/transform HTTP/1.1
Host: api.prexview.com
Authorization: {{token}}
```

