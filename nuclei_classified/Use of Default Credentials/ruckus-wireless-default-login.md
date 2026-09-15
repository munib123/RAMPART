# Nuclei Template: Ruckus Wireless - Default Login
**Template ID:** ruckus-wireless-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**CWE:** CWE-1391
**Source:** Nuclei Template (`ruckus-wireless-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Ruckus Wireless router contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /forms/doLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_username={{username}}&password={{password}}
```

## References
- https://docs.commscope.com/bundle/fastiron-08092-securityguide/page/GUID-32D3BB01-E600-4FBE-B555-7570B5024D34.html
