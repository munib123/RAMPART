# Vulnerability: Scanii API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-scanii.yaml`)

## Description
Simple REST API that can scan submitted documents/files for the presence of threats

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.scanii.com/v2.1/ping HTTP/1.1
Authorization: Basic {{base64(api + ':' + secret)}}
Host: api.scanii.com
```

