# Vulnerability: Apache Apisix Admin - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`apisix-default-login.yaml`)

## Description
An Apache Apisix default admin login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /apisix/admin/user/login HTTP/1.1
Host: {{Hostname}}
Accept: application/json
Authorization:
Content-Type: application/json;charset=UTF-8

{"username":"{{user}}","password":"{{pass}}"}
```

