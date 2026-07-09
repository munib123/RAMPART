# Nuclei Template: Batflat CMS - Default Login
**Template ID:** batflat-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`batflat-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Batflat CMS is vulnerable to default login vulnerability that most commonly affects devices having some pre-set (default) administrative credentials to access all configuration settings.

## Steps to reproduce / Exploit Payload
```http
POST /admin/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&login=
```

## References
- https://www.exploitalert.com/view-details.html?id=34749
- https://cxsecurity.com/issue/WLB-2020010100
