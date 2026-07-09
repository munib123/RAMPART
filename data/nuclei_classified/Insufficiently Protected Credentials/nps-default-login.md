# Nuclei Template: NPS Default Login
**Template ID:** nps-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`nps-default-login.yaml`)

## Vulnerability Information & PoC

## Description
NPS default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login/verify HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{Hostname}}/login/index

username={{username}}&password={{password}}
```

## References
- https://docs.microfocus.com/NNMi/10.30/Content/Administer/Hardening/confCC2b_pwd.htm
