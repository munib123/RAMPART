# Nuclei Template: NetSUS Server Default Login
**Template ID:** netsus-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`netsus-default-login.yaml`)

## Vulnerability Information & PoC

## Description
NetSUS Server default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /webadmin/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

loginwith=suslogin&username={{username}}&password={{password}}&submit=
```

