# Nuclei Template: SOPlanning - Default Login
**Template ID:** soplanning-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`soplanning-default-login.yaml`)

## Vulnerability Information & PoC

## Description
SOPlanning contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /process/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login={{username}}&password={{password}}
```

## References
- https://www.soplanning.org/en/
