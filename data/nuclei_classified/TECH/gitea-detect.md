# Vulnerability: Gitea Detect
**Classification:** TECH
**Source:** Nuclei Template (`gitea-detect.yaml`)

## Description
Gitea was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user/login
```

