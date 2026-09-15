# Nuclei Template: PhotoPrism - Default Login
**Template ID:** photoprism-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`photoprism-default-login.yaml`)

## Vulnerability Information & PoC

## Description
PhotoPrism is an AI-powered photos app for the decentralized web. This template detects instances using default credentials (admin:admin321).

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/session HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","code":""}
```

## References
- https://docs.photoprism.app/getting-started/
