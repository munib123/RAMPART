# Nuclei Template: Apache Doris - Default Login
**Template ID:** doris-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`doris-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Tests if Apache Doris Panel, it is an easy-to-use, high performance and unified analytics database, is using the default password on root/admin user accounts.

## Steps to reproduce / Exploit Payload
```http
POST /rest/v1/login HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{basicAuth}}
Content-Type: application/json; charset=utf-8
```

