# Vulnerability: Redis Commander - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`redis-commander-default-login.yaml`)

## Description
Redis Commander Default Login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

