# Nuclei Template: RiteCMS - Default Login
**Template ID:** ritecms-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ritecms-default-login.yaml`)

## Vulnerability Information & PoC

## Description
RiteCMS Default Credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{path}}admin.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&userpw={{password}}
```

## References
- https://ritecms.com/
