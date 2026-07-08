# Vulnerability: Blitapp API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-blitapp.yaml`)

## Description
Schedule screenshots of web pages and sync them to your cloud storage

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://blitapp.com/api/scheduledcapture HTTP/1.1
Host: blitapp.com
Accept: application/json
Api-key: {{token}}
```

