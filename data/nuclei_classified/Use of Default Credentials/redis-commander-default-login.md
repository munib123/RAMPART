# Nuclei Template: Redis Commander - Default Login
**Template ID:** redis-commander-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`redis-commander-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Redis Commander Default Login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

