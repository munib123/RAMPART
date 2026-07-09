# Nuclei Template: secnet ac - Default Admin Login
**Template ID:** secnet-ac-default-password
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`secnet-ac-default-login.yaml`)

## Vulnerability Information & PoC

## Description
secnet ac default admin credentials were successful.

## Steps to reproduce / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password={{password}}
```

## References
- https://bbs.secnet.cn/post/t-30
