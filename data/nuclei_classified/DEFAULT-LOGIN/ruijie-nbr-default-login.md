# Vulnerability: Ruijie NBR Series Routers - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`ruijie-nbr-default-login.yaml`)

## Description
Ruijie NBR Series Routers Default Login username and password was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/login.html

user={{username}}&password={{password}}
```

