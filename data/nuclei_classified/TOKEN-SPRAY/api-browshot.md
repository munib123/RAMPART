# Vulnerability: Browshot API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-browshot.yaml`)

## Description
Easily make screenshots of web pages in any screen size, as any device

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.browshot.com/api/v1/simple?url=http://mobilito.net/&instance_id=12&width=640&height=480&key={{token}}
```

