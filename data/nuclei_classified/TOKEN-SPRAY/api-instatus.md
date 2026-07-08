# Vulnerability: Instatus API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-instatus.yaml`)

## Description
Post to and update maintenance and incidents on your status page through an HTTP REST API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.instatus.com/v1/pages
```

