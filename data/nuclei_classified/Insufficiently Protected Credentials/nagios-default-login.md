# Nuclei Template: Nagios Default Login
**Template ID:** nagios-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`nagios-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Nagios default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /nagios/side.php HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://www.nagios.org
