# Nuclei Template: Magnolia CMS Default Login - Detect
**Template ID:** magnolia-default-login
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`magnolia-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Magnolia CMS default login credentials were detected.

## Steps to reproduce / Exploit Payload
```http
GET /.magnolia/admincentral HTTP/1.1
Host: {{Hostname}}

POST /.magnolia/admincentral HTTP/1.1
Host: {{Hostname}}
Cookie: csrf={{csrf}};JSESSIONID={{session}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/.magnolia/admincentral

mgnlUserId={{username}}&mgnlUserPSWD={{password}}&csrf={{csrf}}

GET /.magnolia/admincentral/PUSH?v-uiId=1 HTTP/1.1
Host: {{Hostname}}
Cookie: csrf={{csrf}}; JSESSIONID={{session}}
```

## References
- https://www.magnolia-cms.com/
