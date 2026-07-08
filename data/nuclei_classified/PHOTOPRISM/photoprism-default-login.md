# Vulnerability: PhotoPrism - Default Login
**Classification:** PHOTOPRISM
**Source:** Nuclei Template (`photoprism-default-login.yaml`)

## Description
PhotoPrism is an AI-powered photos app for the decentralized web. This template detects instances using default credentials (admin:admin321).

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/session HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","code":""}
```

