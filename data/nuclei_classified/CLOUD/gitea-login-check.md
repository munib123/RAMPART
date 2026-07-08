# Vulnerability: gitea.com Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`gitea-login-check.yaml`)

## Description
Checks for a valid gitea account.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://gitea.com/user/login HTTP/1.1
Host: gitea.com
Content-Type: application/x-www-form-urlencoded

user_name={{username}}&password={{password}}
```

