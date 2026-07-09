# Nuclei Template: Apache InLong - Default Login
**Template ID:** apache-inlong-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`apache-inlong-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache InLong server enables default admin credentials. An attacker can execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /inlong/manager/api/anno/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://github.com/apache/inlong/
