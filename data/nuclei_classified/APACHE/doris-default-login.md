# Vulnerability: Apache Doris - Default Login
**Classification:** APACHE
**Source:** Nuclei Template (`doris-default-login.yaml`)

## Description
Tests if Apache Doris Panel, it is an easy-to-use, high performance and unified analytics database, is using the default password on root/admin user accounts.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /rest/v1/login HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{basicAuth}}
Content-Type: application/json; charset=utf-8
```

