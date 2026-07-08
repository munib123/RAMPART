# Vulnerability: Ruckus Wireless - Default Login
**Classification:** CWE-1391
**Source:** Nuclei Template (`ruckus-wireless-default-login.yaml`)

## Description
Ruckus Wireless router contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /forms/doLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_username={{username}}&password={{password}}
```

