# Vulnerability: Gitea Public Repository - Exposure
**Classification:** GITEA
**Source:** Nuclei Template (`gitea-public-repo-exposure.yaml`)

## Description
Detected publicly accessible Gitea instances exposing repository listings and user information without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/explore/repos
GET {{BaseURL}}/api/v1/repos/search?q=&limit=50
```

