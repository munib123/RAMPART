# Vulnerability: PhotoPrism - Unauth Access
**Classification:** PHOTOPRISM
**Source:** Nuclei Template (`photoprism-unauth.yaml`)

## Description
PhotoPrism is an AI-powered photos app for the decentralized web. This template detects instances that are accessible without authentication, potentially exposing sensitive user data and photos.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v1/config HTTP/1.1
Host: {{Hostname}}
```

