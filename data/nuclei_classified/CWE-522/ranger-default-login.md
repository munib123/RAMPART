# Vulnerability: Apache Ranger - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ranger-default-login.yaml`)

## Description
Apache Ranger contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{user}}&password={{pass}}
```

