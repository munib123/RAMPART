# Vulnerability: OpenSearch Dashboard - Default Login
**Classification:** OPENSEARCH
**Source:** Nuclei Template (`opensearch-default-login.yaml`)

## Description
OpenSearch Dashboard is a community-driven, open source search and analytics suite. This template detects instances using default credentials (admin:admin).

## Vulnerable Code Pattern / Exploit Payload
```http
POST /auth/login HTTP/1.1
Host: {{Hostname}}
osd-xsrf: osd-fetch
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

