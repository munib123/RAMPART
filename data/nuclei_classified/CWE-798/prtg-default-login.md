# Vulnerability: PRTG Network Monitor - Hardcoded Credentials
**Classification:** CWE-798
**Source:** Nuclei Template (`prtg-default-login.yaml`)

## Description
PRTG Network Monitor contains a hardcoded credential vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /public/checklogin.htm HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

loginurl=&username={{username}}&password={{password}}
```

