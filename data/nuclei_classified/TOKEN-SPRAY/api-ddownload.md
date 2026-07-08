# Vulnerability: ddownload API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-ddownload.yaml`)

## Description
File Sharing and Storage

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api-v2.ddownload.com/api/account/info?key={{token}}
```

