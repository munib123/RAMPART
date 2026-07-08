# Vulnerability: Nextcloud Detect
**Classification:** TECH
**Source:** Nuclei Template (`nextcloud-detect.yaml`)

## Description
Nextcloud is a suite of client-server software for creating and using file hosting services

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
GET {{BaseURL}}/nextcloud/login
GET {{BaseURL}}/nextcloud/index.php/login
```

