# Nuclei Template: WebLogic Default Login
**Template ID:** weblogic-weak-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`weblogic-weak-login.yaml`)

## Vulnerability Information & PoC

## Description
WebLogic default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /console/ HTTP/1.1
Host: {{Hostname}}

POST /console/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username={{ username }}&j_password={{ password }}&j_character_encoding=UTF-8
```

## References
- https://github.com/vulhub/vulhub/tree/master/weblogic/weak_password
- https://www.s-squaresystems.com/weblogic-default-admin-users-password-change/
