# Vulnerability: XXL-JOB Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`xxljob-default-login.yaml`)

## Description
XXL-JOB default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
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

