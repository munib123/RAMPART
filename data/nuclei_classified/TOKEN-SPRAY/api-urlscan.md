# Vulnerability: URLScan API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-urlscan.yaml`)

## Description
Scan and Analyse URLs

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://urlscan.io/user/quotas/ HTTP/1.1
Host: urlscan.io
Content-Type: application/json
API-Key: {{token}}
```

