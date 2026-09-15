# Nuclei Template: Samsung Printer - Default Login
**Template ID:** samsung-printer-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`samsung-printer-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Samsung printers contain a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /sws/app/gnb/login/login.jsp HTTP/1.1
Host: {{Hostname}}

Authentication=Basic {{base64(username + ':' + password)}}
```

## References
- https://support.hp.com/gb-en/document/c05591673
