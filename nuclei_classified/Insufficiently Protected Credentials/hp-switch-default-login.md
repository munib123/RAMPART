# Nuclei Template: HP 1820-8G Switch J9979A Default Login
**Template ID:** hp-switch-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`hp-switch-default-login.yaml`)

## Vulnerability Information & PoC

## Description
HP 1820-8G Switch J9979A default admin login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /htdocs/login/login.lua HTTP/1.1
Host: {{Hostname}}

username={{username}}&password=
```

## References
- https://support.hpe.com/hpesc/public/docDisplay?docId=a00077779en_us&docLocale=en_US
